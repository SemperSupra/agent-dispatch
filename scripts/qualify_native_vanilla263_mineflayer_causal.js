'use strict'
// G4 source-only player worker for one isolated runner-owned QEMU native App.
// No Microsoft account, stock client, RCON, broader ingress, or TrueNAS API.
const fs = require('node:fs')
const mineflayer = require('mineflayer')
const { Vec3 } = require('vec3')

const stage = process.env.SUPRACRAFT_NATIVE_STAGE
const prepare = stage === 'candidate-prep'
const port = Number(process.env.MC_PORT)
const output = process.env.BOT_RESULT_FILE
const admitted = ['candidate', 'rollback', 'candidate-prep'].includes(stage) &&
  Number.isSafeInteger(port) && port > 1024 && port < 65536 &&
  typeof output === 'string' && output.length > 0
if (!admitted) process.exit(2)
const result = {
  schema: 'supracraft.native-vanilla263-mineflayer-causal/1',
  classification: 'CLIENT_NOT_QUALIFIED',
  stage, requested_version: '26.3',
  protocol: 777, offline_mode: true,
  synthetic_bot: 'SupraCraftProbe',
  operation: prepare ? 'mineflayer.chat.fixedFixture' : 'mineflayer.placeBlock',
  rcon_used: false,
  backend_independent_oracle_qualified: false,
  true_nas_physical_apply: false,
  collage_mutation_authorized: false,
  in_guest_server_world: false,
  fixture_via_bounded_bot_commands: false,
  placed: false, visible_effect_correct: false
}
let done = false
let bot
function save () { fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n') }
function finish (ok, code) {
  if (done) return
  done = true
  result.classification = ok ? (prepare ? 'CLIENT_FIXTURE_PREPARED' : 'CLIENT_CAUSAL_VISIBILITY') : 'CLIENT_REFUSED'
  if (!ok) result.reason_code = code
  save()
  try { bot?.quit('synthetic native world test complete') } catch {}
  setTimeout(() => process.exit(ok ? 0 : 1), 200)
}
function read (x, y, z) {
  const block = bot.blockAt(new Vec3(x, y, z))
  return block ? block.name : null
}
try {
  bot = mineflayer.createBot({
    host: '127.0.0.1', port, username: 'SupraCraftProbe',
    auth: 'offline', version: '26.3'
  })
} catch (_) { finish(false, 'CLIENT_CONSTRUCT_REFUSED') }
bot?.on('error', () => finish(false, 'CLIENT_ERROR'))
bot?.on('kicked', () => finish(false, 'CLIENT_KICKED'))
bot?.on('end', () => { if (!done) finish(false, 'CLIENT_ENDED') })
bot?.once('spawn', async () => {
  try {
    result.connected_and_spawned = true
    result.negotiated_version = bot.version
    result.negotiated_protocol = bot.protocolVersion
    if (bot.version !== '26.3' || bot.protocolVersion !== 777) {
      return finish(false, 'CLIENT_VERSION_DRIFT')
    }
    const commands = [
      '/forceload add 0 0',
      '/fill -2 69 -2 4 69 3 minecraft:stone',
      '/fill -2 70 -2 4 72 3 minecraft:air',
      '/setblock 0 70 0 minecraft:air',
      '/setblock 2 70 0 minecraft:iron_bars',
      '/setblock 1 70 1 minecraft:black_concrete',
      '/gamemode survival SupraCraftProbe',
      '/give SupraCraftProbe minecraft:redstone_block 1',
      '/tp SupraCraftProbe 0.5 70.0 2.5 180 0'
    ]
    // This single synthetic offline bot must be an OP under the exact
    // source-admitted QEMU-only overlay, never under the normal online App.
    for (const command of commands) {
      bot.chat(command)
      await bot.waitForTicks(8)
    }
    result.fixture_via_bounded_bot_commands = true
    await bot.waitForTicks(20)
    const before = read(0, 70, 0)
    const support = read(0, 69, 0)
    if (before !== 'air' || support !== 'stone') {
      return finish(false, 'CLIENT_FIXTURE_NOT_PRESENT')
    }
    if (prepare) {
      result.expected_datapack_present = true
      result.visible_effect_correct = before === 'air' && support === 'stone' &&
        read(2, 70, 0) === 'iron_bars' &&
        read(1, 70, 1) === 'black_concrete'
      return finish(result.visible_effect_correct,
                    'CLIENT_FIXTURE_PREPARATION_FAILED')
    }
    const deadline = Date.now() + 20000
    let core
    while (Date.now() < deadline) {
      core = bot.inventory.items().find(item => item.name === 'redstone_block')
      if (core) break
      await bot.waitForTicks(2)
    }
    if (!core) return finish(false, 'CLIENT_ITEM_NOT_GRANTED')
    await bot.equip(core, 'hand')
    await bot.waitForTicks(6)
    await bot.placeBlock(bot.blockAt(new Vec3(0, 69, 0)), new Vec3(0, 1, 0))
    await bot.waitForTicks(25)
    const after = read(0, 70, 0)
    const access = read(2, 70, 0)
    const feedback = read(1, 70, 1)
    result.placed = after === 'redstone_block'
    result.visible_effect_correct = result.placed &&
      (stage === 'candidate'
        ? access === 'air' && feedback === 'sea_lantern'
        : access === 'iron_bars' && feedback === 'black_concrete')
    result.expected_datapack_present = stage === 'candidate'
    if (!result.visible_effect_correct) {
      return finish(false, 'CLIENT_CAUSAL_EFFECT_ABSENT')
    }
    finish(true)
  } catch (_) { finish(false, 'CLIENT_EXECUTION_REFUSED') }
})
setTimeout(() => finish(false, 'CLIENT_TIMEOUT'), 120000)
