import { readFileSync } from 'node:fs';
import * as crypto from 'node:crypto';
import * as bcrypt from 'bcrypt';

import { Config } from './config-loader.ts';
import { OAuth } from './oauth.ts';
import { ActionError, type ActionContext, type QueryHandler } from './server.ts';
import * as tables from './tables.ts';
import { Session } from './user.ts';
import { escapeHTML, time, toID } from './utils.ts';

type DiscordUser = { id: string, username: string, global_name: string | null, avatar: string | null };

export const Discord = new class {
	readonly authorizeURL = 'https://discord.com/oauth2/authorize';
	readonly tokenURL = 'https://discord.com/api/oauth2/token';
	readonly userURL = 'https://discord.com/api/users/@me';
	readonly ticketTime = 10 * 60;

	readonly callbackPage = readFileSync(import.meta.dirname + "/public/discord-callback.html", 'utf-8');

	getConfig() {
		const config = Config.discord;
		if (!config?.clientid || !config.clientsecret || !config.redirecturi) {
			throw new ActionError("Discord login is not configured on this server.", 500);
		}
		return config;
	}

	sign(data: string) {
		return crypto.createHmac('sha256', Config.privatekey).update(data).digest('hex');
	}

	seal(payload: { [k: string]: string }) {
		const data = Buffer.from(JSON.stringify({ ...payload, time: time() })).toString('base64url');
		return `${data}.${this.sign(data)}`;
	}

	unseal(sealed?: string): { [k: string]: string } {
		const [data, signature] = (sealed || '').split('.');
		if (!data || !signature) throw new ActionError("Your Discord login expired. Please try again.");
		const expected = Buffer.from(this.sign(data));
		const given = Buffer.from(signature);
		let payload;
		try {
			if (expected.length === given.length && crypto.timingSafeEqual(expected, given)) {
				payload = JSON.parse(Buffer.from(data, 'base64url').toString());
			}
		} catch {}
		if (!payload) {
			throw new ActionError("Your Discord login could not be verified. Please try again.");
		}
		if (time() - Number(payload.time) > this.ticketTime) {
			throw new ActionError("Your Discord login expired. Please try again.");
		}
		return payload;
	}

	getAuthorizeURL(challstr: string, serverid: string) {
		const config = this.getConfig();
		const url = new URL(this.authorizeURL);
		url.searchParams.set('client_id', config.clientid);
		url.searchParams.set('redirect_uri', config.redirecturi);
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('scope', 'identify');
		url.searchParams.set('state', this.seal({ challstr, serverid }));
		return url.toString();
	}

	async exchangeCode(code: string) {
		const config = this.getConfig();
		const response = await fetch(this.tokenURL, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				client_id: config.clientid,
				client_secret: config.clientsecret,
				grant_type: 'authorization_code',
				code,
				redirect_uri: config.redirecturi,
			}),
		});
		const data = response.ok ? await response.json() as { access_token?: string } : null;
		if (!data?.access_token) {
			throw new ActionError("Discord rejected this login. Please try again.");
		}
		return data.access_token;
	}

	async fetchUser(accessToken: string): Promise<DiscordUser> {
		const response = await fetch(this.userURL, { headers: { Authorization: `Bearer ${accessToken}` } });
		const data = response.ok ? await response.json() as Partial<DiscordUser> : null;
		if (!data?.id || !data.username) {
			throw new ActionError("Could not read your Discord account. Please try again.");
		}
		return { id: data.id, username: data.username, global_name: data.global_name || null, avatar: data.avatar || null };
	}

	suggestName(user: DiscordUser) {
		for (const candidate of [user.username, user.global_name]) {
			const userid = toID(candidate).slice(0, 18);
			if (/[a-z]/.test(userid) && !userid.startsWith('guest') && Session.isUseridAllowed(userid)) {
				return userid;
			}
		}
		return '';
	}

	saveProfile(user: DiscordUser) {
		return tables.discordProfiles.set(user.id, {
			username: user.username, globalname: user.global_name, avatar: user.avatar, time: time(),
		});
	}

	avatarURL(discordid: string, avatar: string | null) {
		return avatar ? `https://cdn.discordapp.com/avatars/${discordid}/${avatar}.png?size=64` :
			`https://cdn.discordapp.com/embed/avatars/${Number((BigInt(discordid) >> 22n) % 6n)}.png`;
	}

	async profiles(ids: string[]) {
		ids = [...new Set(ids.filter(id => /^\d{1,20}$/.test(id)))].slice(0, 100);
		if (!ids.length) return [];
		const links = await tables.discordLinks.selectAll(['userid', 'discordid'])`WHERE discordid IN (${ids})`;
		const userids = links.map(link => link.userid);
		const users = userids.length ?
			await tables.users.selectAll(['userid', 'username', 'logintime'])`WHERE userid IN (${userids})` : [];
		const profiles = await tables.discordProfiles.selectAll()`WHERE discordid IN (${ids})`;
		return ids.map(discordid => {
			const names = users.filter(user => links.some(link => link.discordid === discordid && link.userid === user.userid))
				.sort((a, b) => Number(b.logintime || 0) - Number(a.logintime || 0));
			const profile = profiles.find(each => each.discordid === discordid);
			if (!names.length) return null;
			return {
				discordid, name: names[0].username, names: names.map(user => user.username),
				username: profile?.username || null, globalname: profile?.globalname || null,
				avatar: this.avatarURL(discordid, profile?.avatar || null),
			};
		}).filter(Boolean);
	}

	async search(query: string) {
		const id = toID(query);
		const text = query.trim().slice(0, 32);
		if (!id && !text) return [];
		const found = new Set<string>();
		for (const link of await tables.discordLinks.selectAll(['discordid'])`WHERE userid LIKE ${`%${id}%`} LIMIT 20`) {
			found.add(link.discordid);
		}
		const like = `%${text}%`;
		const profiles = await tables.discordProfiles.selectAll(['discordid'])`
			WHERE username LIKE ${like} OR globalname LIKE ${like} LIMIT 20`;
		for (const profile of profiles) found.add(profile.discordid);
		const rank = (profile: { name: string, names: string[], username: string | null, globalname: string | null }) => {
			const all = [...profile.names, profile.username || '', profile.globalname || ''].map(toID);
			return all.includes(id) ? 0 : all.some(each => each.startsWith(id)) ? 1 : 2;
		};
		const results = await this.profiles([...found]);
		return results.sort((a, b) => rank(a!) - rank(b!) || a!.name.localeCompare(b!.name)).slice(0, 10);
	}

	getLinkedUser(discordid: string) {
		return tables.users.selectOne()`WHERE userid IN (
			SELECT userid FROM "${tables.discordLinks.name}" WHERE discordid = ${discordid}
		) ORDER BY registertime`;
	}

	async link(discordid: string, username: string, ip: string) {
		const userid = toID(username);
		if (!userid) throw new ActionError(`You must specify a username.`);
		if (!/[a-z]/.test(userid)) throw new ActionError(`Your username must include at least one letter.`);
		if (userid.startsWith('guest')) throw new ActionError(`Your username cannot start with 'guest'.`);
		if (userid.length > 18) throw new ActionError(`Your username must be less than 19 characters long.`);
		if (!Session.isUseridAllowed(userid)) throw new ActionError(`Your username contains disallowed text.`);
		const user = await tables.users.insertIgnore({
			userid, username, passwordhash: null, email: null, registertime: time(), ip,
		});
		if (!user.affectedRows) throw new ActionError(`Your username is already taken.`);
		await tables.discordLinks.set(userid, { discordid, time: time() });
		return userid;
	}

	async logIn(context: ActionContext, username: string, challstr: string) {
		const { session } = context;
		const user = await context.getUser();
		await session.logout();
		session.sidhash = await session.makeSid();
		session.session = (await tables.sessions.insert({
			userid: toID(username),
			sid: await bcrypt.hash(session.sidhash, Config.passwordSalt),
			time: time(),
			timeout: time() + 2 * 7 * 24 * 60 * 60,
			ip: context.getIp(),
		})).insertId || 0;
		await user.login(username);
		await session.setSid();
		return session.getAssertion(toID(username), Config.challengekeyid, null, challstr);
	}

	renderCallbackPage(values: { [k: string]: string }) {
		return this.callbackPage.replace(
			/\{\{(\w+)\}\}/g, (match, key: string) => escapeHTML({ root: Config.routes.root, ...values }[key] || '')
		);
	}
};

export const discordActions: { [k: string]: QueryHandler } = {
	'discord/login'(params) {
		if (!params.challstr) throw new ActionError("No challstr provided.");
		this.response.statusCode = 302;
		this.setHeader('Location', Discord.getAuthorizeURL(params.challstr, params.serverid || ""));
		return '';
	},

	async 'discord/callback'(params) {
		let values: { [k: string]: string };
		try {
			if (params.error) throw new ActionError(`Discord login failed: ${params.error}`);
			if (!params.code) throw new ActionError("No code provided.");
			const { challstr, serverid } = Discord.unseal(params.state);
			params.serverid = serverid;
			const discordUser = await Discord.fetchUser(await Discord.exchangeCode(params.code));
			const account = await Discord.getLinkedUser(discordUser.id);
			if (account) await Discord.saveProfile(discordUser);
			values = account ? {
				username: account.username,
				assertion: await Discord.logIn(this, account.username, challstr),
			} : {
				ticket: Discord.seal({
					discordid: discordUser.id, challstr, serverid,
					username: discordUser.username, globalname: discordUser.global_name || '', avatar: discordUser.avatar || '',
				}),
				suggestion: Discord.suggestName(discordUser),
			};
		} catch (e) {
			if (!(e instanceof ActionError)) throw e;
			values = { error: e.message };
		}
		this.response.setHeader('Content-Type', 'text/html');
		return Discord.renderCallbackPage(values);
	},

	async 'discord/api/register'(params) {
		if (this.request.method !== 'POST') {
			throw new ActionError("Registering a Discord account requires POST.");
		}
		if (!OAuth.isSameOriginRequest(this)) {
			throw new ActionError("Registering a Discord account requires a same-origin request.");
		}
		const { discordid, challstr, serverid, username: discordname, globalname, avatar } = Discord.unseal(params.ticket);
		params.serverid = serverid;
		if (await Discord.getLinkedUser(discordid)) {
			throw new ActionError(`This Discord account is already linked to an account.`);
		}
		const username = params.username || "";
		const userid = await Discord.link(discordid, username, this.getIp());
		if (discordname) {
			await Discord.saveProfile({ id: discordid, username: discordname, global_name: globalname || null, avatar: avatar || null });
		}
		const assertion = await Discord.logIn(this, username, challstr);
		return { actionsuccess: !assertion.startsWith(';'), assertion, curuser: { loggedin: true, username, userid } };
	},

	async 'discord/addname'(params) {
		await this.requireServer();
		const link = await tables.discordLinks.get(toID(params.userid));
		if (!link || !params.username) return { actionsuccess: false };
		await Discord.link(link.discordid, params.username, params.ip || '');
		return { actionsuccess: true };
	},

	async 'discord/names'(params) {
		await this.requireServer();
		const discordid = /^\d+$/.test(params.userid || '') ? params.userid :
			(await tables.discordLinks.get(toID(params.userid)))?.discordid;
		if (!discordid) return { names: [] };
		const links = await tables.discordLinks.selectAll(['userid'])`WHERE discordid = ${discordid} ORDER BY time`;
		return { discordid, names: links.map(link => link.userid) };
	},

	async 'discord/profiles'(params) {
		await this.requireServer();
		return { profiles: await Discord.profiles((params.ids || '').split(',')) };
	},

	async 'discord/search'(params) {
		await this.requireServer();
		return { profiles: await Discord.search(params.query || '') };
	},
};

const checkLoggedIn = Reflect.get(Session.prototype, 'checkLoggedIn');
Session.prototype.checkLoggedIn = async function () {
	const sids = (this.context.request.headers.cookie || '').split(';')
		.map(part => part.trim().split('='))
		.filter(([name]) => name === 'sid')
		.map(([, value]) => decodeURIComponent(value));
	if (this.context.body.sid || sids.length < 2) return checkLoggedIn.call(this);
	for (const sid of sids) {
		(this.cookies as Map<string, string>).set('sid', sid);
		const user = await checkLoggedIn.call(this);
		if (user) {
			this.context.response.removeHeader('Set-Cookie');
			return user;
		}
	}
	return null;
};
