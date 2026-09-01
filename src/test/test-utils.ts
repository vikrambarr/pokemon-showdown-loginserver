/**
 * Shared HTTP plumbing for the test suites: start a server, make a request, read the reply.
 */
import { strict as assert } from 'node:assert';
import * as http from 'node:http';

import type { Server } from '../server.ts';

export async function waitForListening(server: Server) {
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

export async function closeServer(server: Server) {
	await new Promise<void>(resolve => {
		server.server.close(() => resolve());
	});
}

export async function httpRequest(
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

export function parseResponse(body: string) {
	assert.equal(body.charAt(0), ']');
	return JSON.parse(body.slice(1));
}
