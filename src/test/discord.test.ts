/**
 * Tests for logging in with Discord.
 */
import { strict as assert } from 'node:assert';
import * as crypto from 'node:crypto';
import * as http from 'node:http';
import { after, before, beforeEach, suite, test } from 'node:test';

import { Config } from '../config-loader.ts';
import { Discord } from '../discord.ts';
import { Server } from '../server.ts';
import * as tables from '../tables.ts';
import { time } from '../utils.ts';

const DISCORD_ID = '123456789012345678';
const CLIENT_ID = '987654321098765432';
const REDIRECT_URI = 'https://play.example/api/discord/callback';

async function waitForListening(server: Server) {
	await new Promise<void>((resolve, reject) => {
		const cleanup = () => {
			server.server.off('listening', onListening);
			server.server.off('error', onError);
		};
		const onListening = () => {
			cleanup();
			resolve();
		};
		const onError = (error: Error) => {
			cleanup();
			reject(error);
		};
		server.server.once('listening', onListening);
		server.server.once('error', onError);
	});
}

async function closeServer(server: Server) {
	await new Promise<void>(resolve => {
		server.server.close(() => resolve());
	});
}

async function httpRequest(
	server: Server,
	path: string,
	options: {
		method?: string,
		headers?: http.OutgoingHttpHeaders,
		body?: string,
	} = {}
) {
	const address = server.server.address();
	assert(address && typeof address === 'object');
	return new Promise<{
		statusCode: number | undefined,
		body: string,
		headers: http.IncomingHttpHeaders,
	}>((resolve, reject) => {
		const req = http.request({
			host: '127.0.0.1',
			port: address.port,
			path,
			method: options.method,
			headers: options.headers,
		}, response => {
			let body = '';
			response.setEncoding('utf8');
			response.on('data', chunk => {
				body += chunk;
			});
			response.on('end', () => resolve({
				statusCode: response.statusCode,
				body,
				headers: response.headers,
			}));
		});
		req.on('error', reject);
		req.end(options.body);
	});
}

function parseResponse(body: string) {
	assert.equal(body.charAt(0), ']');
	return JSON.parse(body.slice(1));
}

void suite('Discord login', () => {
	let server: Server;
	let serverOrigin = '';
	let oldPrivateKey: string;

	async function register(ticket: string, username: string) {
		return httpRequest(server, '/api/discord/api/register', {
			method: 'POST',
			headers: {
				origin: serverOrigin,
				'content-type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({ ticket, username }).toString(),
		});
	}

	void before(async () => {
		server = new Server(0, '127.0.0.1');
		await waitForListening(server);
		const address = server.server.address();
		assert(address && typeof address === 'object');
		serverOrigin = `http://127.0.0.1:${address.port}`;

		oldPrivateKey = Config.privatekey;
		Config.privatekey = crypto.generateKeyPairSync('rsa', {
			modulusLength: 1024,
		}).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

		Config.discord = {
			clientid: CLIENT_ID,
			clientsecret: 'notasecret',
			redirecturi: REDIRECT_URI,
			guildid: null,
		};
	});

	void after(async () => {
		Config.privatekey = oldPrivateKey;
		Config.discord = null;
		Config.discordonly = false;
		await closeServer(server);
	});

	void beforeEach(async () => {
		Config.discordonly = false;
		await tables.discordLinks.deleteAll()``;
		await tables.users.deleteAll()`WHERE userid LIKE 'discord%'`;
	});

	void test('seals tickets against tampering and replay', () => {
		const sealed = Discord.seal({ discordid: DISCORD_ID, challstr: '4|abcdef' });
		assert.deepEqual(
			{ discordid: Discord.unseal(sealed).discordid, challstr: Discord.unseal(sealed).challstr },
			{ discordid: DISCORD_ID, challstr: '4|abcdef' }
		);

		const [data, signature] = sealed.split('.');
		const flipped = signature.startsWith('0') ? `1${signature.slice(1)}` : `0${signature.slice(1)}`;
		assert.throws(() => Discord.unseal(`${data}.${flipped}`), /could not be verified/);
		assert.throws(() => Discord.unseal(`${data}.${signature}beef`), /could not be verified/);
		assert.throws(() => Discord.unseal(data), /expired/);
		assert.throws(() => Discord.unseal(''), /expired/);

		const stale = Buffer.from(JSON.stringify({
			discordid: DISCORD_ID, time: time() - 60 * 60,
		})).toString('base64url');
		assert.throws(() => Discord.unseal(`${stale}.${Discord.sign(stale)}`), /expired/);
	});

	void test('sends users to Discord with the challstr sealed into the state', async () => {
		const missing = await httpRequest(server, '/api/discord/login');
		assert.equal(parseResponse(missing.body).actionerror, 'No challstr provided.');

		const response = await httpRequest(server, '/api/discord/login?challstr=4%7Cabcdef&serverid=showdown');
		assert.equal(response.statusCode, 302);
		const location = new URL(response.headers.location!);
		assert.equal(location.origin + location.pathname, 'https://discord.com/oauth2/authorize');
		assert.equal(location.searchParams.get('client_id'), CLIENT_ID);
		assert.equal(location.searchParams.get('redirect_uri'), REDIRECT_URI);
		assert.equal(location.searchParams.get('response_type'), 'code');
		assert.equal(location.searchParams.get('scope'), 'identify');
		const state = Discord.unseal(location.searchParams.get('state')!);
		assert.equal(state.challstr, '4|abcdef');
		assert.equal(state.serverid, 'showdown');
	});

	void test('asks for guild membership scope only when a guild is configured', () => {
		Config.discord!.guildid = '111222333444555666';
		const location = new URL(Discord.getAuthorizeURL('4|abcdef', 'showdown'));
		assert.equal(location.searchParams.get('scope'), 'identify guilds.members.read');
		Config.discord!.guildid = null;
	});

	void test('suggests a username from the Discord handle', () => {
		assert.equal(Discord.suggestName({ id: DISCORD_ID, username: 'some.handle_1', global_name: null }), 'somehandle1');
		assert.equal(Discord.suggestName({ id: DISCORD_ID, username: '._.', global_name: 'Red' }), 'red');
		assert.equal(Discord.suggestName({ id: DISCORD_ID, username: '._.', global_name: '🌸🌸' }), '');
		assert.equal(Discord.suggestName({ id: DISCORD_ID, username: 'guest_1234', global_name: null }), '');
		assert.equal(
			Discord.suggestName({ id: DISCORD_ID, username: 'averyveryverylonghandle', global_name: null }).length,
			18
		);
	});

	void test('renders a page that signs up or hands back the assertion', () => {
		const signup = Discord.renderCallbackPage({ ticket: 'tkt', suggestion: 'somehandle1' });
		assert.match(signup, /data-ticket="tkt"/);
		assert.match(signup, /data-suggestion="somehandle1"/);
		assert.match(signup, /\$\.post\('\/api\/discord\/api\/register'/);
		assert.doesNotMatch(signup, /\{\{\w+\}\}/);

		const loggedIn = Discord.renderCallbackPage({ username: 'Someone', assertion: 'a,b;c' });
		assert.match(loggedIn, /data-assertion="a,b;c"/);
		assert.match(loggedIn, /postMessage/);

		assert.match(Discord.renderCallbackPage({ suggestion: '<script>' }), /data-suggestion="&lt;script&gt;"/);
	});

	void test('names and links the account on first login', async () => {
		const ticket = Discord.seal({ discordid: DISCORD_ID, challstr: 'discordchallenge' });
		const response = await register(ticket, 'DiscordFixture');
		const result = parseResponse(response.body);

		assert(result.actionsuccess, result.actionerror);
		assert.equal(result.curuser.userid, 'discordfixture');
		assert(!result.assertion.startsWith(';'), result.assertion);

		assert.equal((await tables.discordLinks.get(DISCORD_ID))?.userid, 'discordfixture');
		const user = await tables.users.get('discordfixture');
		assert.equal(user?.username, 'DiscordFixture');
		assert.equal(user?.passwordhash, null);

		const setCookie = response.headers['set-cookie']?.[0];
		assert(setCookie);
		const upkeep = await httpRequest(server, '/api/upkeep?challstr=discordchallenge', {
			headers: { cookie: /^sid=[^;]+/.exec(setCookie)![0] },
		});
		const session = parseResponse(upkeep.body);
		assert.equal(session.loggedin, true);
		assert.equal(session.username, 'DiscordFixture');
	});

	void test('refuses a taken name, a reused Discord account, and a name it would not suggest', async () => {
		const ticket = Discord.seal({ discordid: DISCORD_ID, challstr: 'discordchallenge' });
		assert(parseResponse((await register(ticket, 'DiscordFixture')).body).actionsuccess);

		const other = Discord.seal({ discordid: '222222222222222222', challstr: 'discordchallenge' });
		assert.equal(
			parseResponse((await register(other, 'DiscordFixture')).body).actionerror,
			'Your username is already taken.'
		);
		assert.equal(await tables.discordLinks.get('222222222222222222'), undefined);

		assert.equal(
			parseResponse((await register(ticket, 'DiscordSecond')).body).actionerror,
			'This Discord account is already linked to an account.'
		);
		assert.equal(await tables.users.get('discordsecond'), undefined);

		for (const [name, error] of [
			['', 'You must specify a username.'],
			['1234', 'Your username must include at least one letter.'],
			['guestdiscord', `Your username cannot start with 'guest'.`],
			['discordaveryverylongname', 'Your username must be less than 19 characters long.'],
		] as const) {
			const attempt = Discord.seal({ discordid: '333333333333333333', challstr: 'discordchallenge' });
			assert.equal(parseResponse((await register(attempt, name)).body).actionerror, error);
		}
	});

	void test('requires a same-origin POST to name an account', async () => {
		const ticket = Discord.seal({ discordid: DISCORD_ID, challstr: 'discordchallenge' });

		const get = await httpRequest(server, `/api/discord/api/register?${new URLSearchParams({
			ticket, username: 'DiscordFixture',
		})}`);
		assert.equal(parseResponse(get.body).actionerror, 'Registering a Discord account requires POST.');

		const crossOrigin = await httpRequest(server, '/api/discord/api/register', {
			method: 'POST',
			headers: {
				origin: 'https://attacker.example',
				'content-type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({ ticket, username: 'DiscordFixture' }).toString(),
		});
		assert.equal(
			parseResponse(crossOrigin.body).actionerror,
			'Registering a Discord account requires a same-origin request.'
		);
		assert.equal(await tables.users.get('discordfixture'), undefined);
	});

	void test('asks for Discord instead of a password when discordonly is set', async () => {
		assert(parseResponse((await register(
			Discord.seal({ discordid: DISCORD_ID, challstr: 'discordchallenge' }), 'DiscordFixture'
		)).body).actionsuccess);

		const ask = (userid: string) => server.request('getassertion', {
			userid,
			challstr: 'discordchallenge',
			challengekeyid: `${Config.challengekeyid}`,
		}).then(response => response.result);

		assert.equal(await ask('discordfixture'), ';');
		assert(!(await ask('discordstranger')).startsWith(';'));

		Config.discordonly = true;
		assert.equal(await ask('discordfixture'), ';;@discord');
		assert.equal(await ask('discordstranger'), ';;@discord');
	});

	void test('leaves the password actions to registered servers when discordonly is set', async () => {
		Config.discordonly = true;
		const challstr = crypto.randomBytes(32).toString('hex');

		const attempts: Record<string, string>[] = [
			{ act: 'register', username: 'DiscordPassword', password: 'applesauce', cpassword: 'applesauce', captcha: 'pikachu' },
			{ act: 'login', name: 'DiscordPassword', pass: 'applesauce' },
			{ act: 'changepassword', oldpassword: 'applesauce', password: 'x', cpassword: 'x' },
		];
		for (const body of attempts) {
			const response = await httpRequest(server, `/action.php?${new URLSearchParams({
				...body, challstr, challengekeyid: `${Config.challengekeyid}`,
			})}`, { method: 'POST' });
			assert.match(
				parseResponse(response.body).actionerror,
				/can only be used by a registered server/,
				`${body.act} was not gated`
			);
		}
		assert.equal(await tables.users.get('discordpassword'), undefined);
	});
});
