import {spawn} from 'node:child_process';
import {mkdir,readdir,writeFile} from 'node:fs/promises';
const files=(await readdir('test')).filter(f=>f.endsWith('.test.mjs')).sort().map(f=>'test/'+f);
const child=spawn(process.execPath,['--test','--test-reporter=tap',...files],{stdio:['ignore','pipe','pipe'],env:process.env});
let output='',errors='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>errors+=b);
const code=await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',resolve);});
await mkdir('artifacts/validation',{recursive:true});
await writeFile('artifacts/validation/acceptance.tap',output+errors,{mode:0o600});
const count=key=>Number(output.match(new RegExp('^# '+key+' (\\d+)$','m'))?.[1]??NaN);
const result={tests:count('tests'),pass:count('pass'),fail:count('fail'),skipped:count('skipped'),cancelled:count('cancelled'),exit_code:code};
const ok=code===0&&result.tests>0&&result.tests===result.pass&&result.fail===0&&result.skipped===0&&result.cancelled===0;
await writeFile('artifacts/validation/acceptance-summary.json',JSON.stringify({...result,accepted:ok},null,2),{mode:0o600});
console.log(JSON.stringify({...result,accepted:ok}));
if(!ok){console.error('Acceptance failed: tests must all pass with zero skips. See artifacts/validation/acceptance.tap.');process.exitCode=1;}
