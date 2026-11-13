import assert from 'node:assert/strict';
import { SkillsClient } from '@modelcontextprotocol/client/ext/skills';

export async function verifySkills(client) {
  const skills = new SkillsClient(client);
  assert.equal(skills.supported, true);
  const listing = await skills.list();
  assert.equal(listing.skills.length, 1);
  const { skill } = await skills.get('skill://app-security/SKILL.md');
  const file = await skills.read(skill);
  assert.equal(file.verified, true);
  assert.equal(file.frontmatter.name, 'app-security');
  const resources = await client.listResources();
  assert.ok(resources.resources.some(r => r.uri === skill.uri));
  const workflow = await client.callTool({ name: 'get_workflow', arguments: {} });
  assert.equal(workflow.content[0].text, file.text);
  await assert.rejects(client.readResource({ uri: 'skill://app-security/../../.env' }));
  await assert.rejects(skills.get('skill://missing/SKILL.md'));
}
