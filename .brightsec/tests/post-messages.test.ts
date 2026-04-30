import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /messages', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'xss', 'sqli', 'ssrf', 'osi', 'file_upload'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        code_source: 'carlcj/damn-vulnerable-MCP-server:bright/ea6b706b-216d-5557-b7f0-b3d9339f7669',
        user_roles: null
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/messages`,
      body: {
        message: 'Test message'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});