import { strict as assert } from 'node:assert';
import * as crypto from 'node:crypto';
import { once } from 'node:events';
import { after, before, beforeEach, suite, test } from 'node:test';

import { Config } from '../config-loader.ts';
import { Server } from '../server.ts';
import { Discord } from '../discord.ts';
import * as tables from '../tables.ts';
import { time } from '../utils.ts';

const DISCORD_ID = '123456789012345678';
const SERVER = { serverid: 'showdown', servertoken: '42354y6dhgfdsretr' };

void suite('Discord login', () => {
	let server: Server;
	let origin = '';
	let oldPrivateKey: string;

	const ticket = (discordid = DISCORD_ID) => Discord.seal({ discordid, challstr: 'discordchallenge' });
	const act = async (name: string, params: { [k: string]: string } = {}) => (await server.request(name, params)).result;

	async function register(sealed: string, username: string, headers: { [k: string]: string } = { origin }) {
		const response = await fetch(`${origin}/api/discord/api/register`, {
			method: 'POST', headers, body: new URLSearchParams({ ticket: sealed, username }),
		});
		return { result: JSON.parse((await response.text()).slice(1)), cookie: response.headers.getSetCookie()[0] };
	}

	async function assertion(userid: string, cookie = '') {
		const query = new URLSearchParams({ userid, challstr: 'discordchallenge', challengekeyid: `${Config.challengekeyid}` });
		return (await fetch(`${origin}/api/getassertion?${query}`, { headers: { cookie } })).text();
	}

	void before(async () => {
		server = new Server(0, '127.0.0.1');
		await once(server.server, 'listening');
		origin = `http://127.0.0.1:${(server.server.address() as { port: number }).port}`;
		oldPrivateKey = Config.privatekey;
		Config.privatekey = crypto.generateKeyPairSync('rsa', {
			modulusLength: 1024,
		}).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
		Config.discord = { clientid: '987654321098765432', clientsecret: 'notasecret', redirecturi: 'https://play.example/cb' };
	});

	void after(async () => {
		Config.privatekey = oldPrivateKey;
		Config.discord = null;
		Config.discordonly = false;
		await server.close();
	});

	void beforeEach(async () => {
		Config.discordonly = false;
		await tables.discordLinks.deleteAll()``;
		await tables.users.deleteAll()`WHERE userid LIKE 'discord%'`;
	});

	void test('seals tickets against tampering and expiry', () => {
		const sealed = ticket();
		assert.equal(Discord.unseal(sealed).discordid, DISCORD_ID);
		const [data, signature] = sealed.split('.');
		const flipped = `${signature.startsWith('0') ? '1' : '0'}${signature.slice(1)}`;
		assert.throws(() => Discord.unseal(`${data}.${flipped}`), /verified/);
		assert.throws(() => Discord.unseal(`${data}.${signature}beef`), /verified/);
		assert.throws(() => Discord.unseal(data), /expired/);
		const stale = Buffer.from(JSON.stringify({ discordid: DISCORD_ID, time: time() - 3600 })).toString('base64url');
		assert.throws(() => Discord.unseal(`${stale}.${Discord.sign(stale)}`), /expired/);
	});

	void test('sends users to Discord with the challstr sealed into the state', async () => {
		assert.equal((await act('discord/login')).actionerror, 'No challstr provided.');
		const { context } = await server.request('discord/login', { challstr: '4|abc', serverid: 'showdown' });
		assert.equal(context.response.statusCode, 302);
		const location = new URL(`${context.response.getHeader('Location')}`);
		assert.equal(location.origin + location.pathname, 'https://discord.com/oauth2/authorize');
		assert.equal(location.searchParams.get('client_id'), '987654321098765432');
		assert.equal(location.searchParams.get('scope'), 'identify');
		assert.deepEqual(Object.values(Discord.unseal(location.searchParams.get('state')!)).slice(0, 2), ['4|abc', 'showdown']);
	});

	void test('suggests a username from the Discord handle', () => {
		const suggest = (username: string, globalName: string | null = null) => (
			Discord.suggestName({ id: DISCORD_ID, username, global_name: globalName })
		);
		assert.equal(suggest('some.handle_1'), 'somehandle1');
		assert.equal(suggest('._.', 'Red'), 'red');
		assert.equal(suggest('._.', '🌸'), '');
		assert.equal(suggest('guest_1234'), '');
		assert.equal(suggest('averyveryverylonghandle').length, 18);
	});

	void test('renders the callback page', async () => {
		const signup = Discord.renderCallbackPage({ ticket: 'tkt', suggestion: '<script>' });
		assert.match(signup, /data-ticket="tkt"/);
		assert.match(signup, /data-suggestion="&lt;script&gt;"/);
		assert.match(signup, new RegExp(`href="//${Config.routes.root}/style/global.css"`));
		assert.doesNotMatch(signup, /\{\{\w+\}\}/);
		for (const [params, error] of [
			[{ error: 'access_denied' }, 'Discord login failed: access_denied'],
			[{ state: 'x' }, 'No code provided.'],
			[{ code: 'x', state: 'bogus.signature' }, 'Your Discord login could not be verified. Please try again.'],
		] as const) {
			assert.match(await act('discord/callback', params), new RegExp(`data-error="${error}"`));
		}
	});

	void test('names and links the account on first login', async () => {
		const { result, cookie } = await register(ticket(), 'DiscordFixture');
		assert(result.actionsuccess, result.actionerror);
		assert.equal(result.curuser.userid, 'discordfixture');
		assert.equal((await Discord.getLinkedUser(DISCORD_ID))?.username, 'DiscordFixture');
		assert.equal((await tables.users.get('discordfixture'))?.passwordhash, null);
		const upkeep = await fetch(`${origin}/api/upkeep?challstr=discordchallenge`, { headers: { cookie } });
		assert.equal(JSON.parse((await upkeep.text()).slice(1)).username, 'DiscordFixture');
	});

	void test('refuses bad registrations', async () => {
		assert((await register(ticket(), 'DiscordFixture')).result.actionsuccess);
		for (const [sealed, name, error] of [
			[ticket('2'), 'DiscordFixture', 'Your username is already taken.'],
			[ticket(), 'DiscordSecond', 'This Discord account is already linked to an account.'],
			[ticket('3'), '', 'You must specify a username.'],
			[ticket('3'), '1234', 'Your username must include at least one letter.'],
			[ticket('3'), 'guestdiscord', `Your username cannot start with 'guest'.`],
			[ticket('3'), 'discordaveryverylongname', 'Your username must be less than 19 characters long.'],
		]) {
			assert.equal((await register(sealed, name)).result.actionerror, error);
		}
		assert.equal(
			(await register(ticket('4'), 'DiscordOther', { origin: 'https://attacker.example' })).result.actionerror,
			'Registering a Discord account requires a same-origin request.'
		);
		assert.equal(await tables.users.get('discordsecond'), undefined);
	});

	void test('lets a Discord login use its linked names and tags its unregistered ones', async () => {
		const { cookie } = await register(ticket(), 'DiscordFixture');
		const addName = (userid: string, username: string) => act('discord/addname', { ...SERVER, userid, username });
		assert((await addName('discordfixture', 'DiscordNick')).actionsuccess);
		assert.match((await addName('discordfixture', 'DiscordNick')).actionerror, /taken/);
		assert.equal((await addName('discordnobody', 'DiscordX')).actionsuccess, false);

		assert.deepEqual((await assertion('discordnick', cookie)).split(',').slice(1, 3), ['discordnick', '2']);
		const unregistered = (await assertion('discordnew', cookie)).split(';')[0].split(',');
		assert.deepEqual([unregistered[2], unregistered[5]], ['1', 'discordfixture']);
		assert.equal((await assertion('discordnew')).split(';')[0].split(',').length, 5);
		assert.equal(await assertion('discordnick'), ';');
	});

	void test('asks for Discord and gates the password actions when discordonly is set', async () => {
		const { cookie } = await register(ticket(), 'DiscordFixture');
		Config.discordonly = true;
		assert.equal(await assertion('discordfixture'), ';;This name needs a Discord login.');
		assert.equal(await assertion('discordstranger'), ';;This name needs a Discord login.');
		assert(!(await assertion('discordstranger', cookie)).startsWith(';'));
		for (const name of ['register', 'login', 'changepassword']) {
			assert.match((await act(name, { username: 'DiscordPassword', password: 'x' })).actionerror, /registered server/, name);
		}
	});

	void test('lists the names linked to a Discord account for servers only', async () => {
		await register(ticket(), 'DiscordFixture');
		await act('discord/addname', { ...SERVER, userid: 'discordfixture', username: 'DiscordAlt' });
		assert.match((await act('discord/names', { userid: 'discordfixture' })).actionerror, /registered server/);
		for (const userid of ['discordfixture', 'discordalt', DISCORD_ID]) {
			assert.deepEqual(await act('discord/names', { ...SERVER, userid }), {
				discordid: DISCORD_ID, names: ['discordfixture', 'discordalt'],
			});
		}
		assert.deepEqual(await act('discord/names', { ...SERVER, userid: 'discordnobody' }), { names: [] });
	});
});
