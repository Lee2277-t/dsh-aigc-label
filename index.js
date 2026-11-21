// dsh-aigc-label —— 给 Office 产物写入 / 查验 AIGC 隐式标识。
//
// 国内对人工智能生成合成内容有标识要求（GB 45438-2025 /《人工智能生成合成内容标识办法》）。
// 隐式标识的载体是 OOXML 包里的 `docProps/custom.xml`，一条名为 AIGC 的自定义属性，
// 值是紧凑 JSON。Office 打开文件时它是不可见的，但检测侧读得到。
//
// 工具：
//   aigc_label_check  扫目录或单个文件：哪些带标识、哪些没带、字段全不全
//   aigc_label_write  写入标识（docx / xlsx / pptx），写完读回校验
//
// 两个刻意的取舍，都在报告里明说：
//   1. 服务提供者编码不内置。它是接入方在备案链路里拿到的 27 位编码，一个插件内置任何一个人
//      的编码都是错的——写进别人的文件，溯源就指到了不相干的主体。没配置就拒绝写入，不猜。
//   2. ReservedCode1/2 留空且不写进 JSON。规范把它定义为"保护内容、标识完整性的信息"，
//      官方算法要接入单发放的私钥；私钥不能随插件分发，本地链路算不出可验签的值。
//      填一个本地随机值只能让字段看起来非空，反而给检测侧制造"像是有效"的假象。

import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import crypto from 'node:crypto'
import Schema from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'aigc-label'
export const inject = ['tools']

export const Config = Schema.object({
  contentProducer: Schema.string()
    .default('')
    .description('生成合成服务提供者编码（27 位，来自接入单）。不配置则拒绝写入。'),
  label: Schema.string().default('1').description('标识取值：1=属于生成合成，2=可能为，3=疑似为。'),
  extensions: Schema.array(Schema.string())
    .default(['.docx', '.xlsx', '.pptx'])
    .description('要处理的 OOXML 扩展名。'),
})

// ---------------------------------------------------------------- OOXML 常量

const CUSTOM_PART = 'docProps/custom.xml'
const CUSTOM_CT = 'application/vnd.openxmlformats-officedocument.custom-properties+xml'
const CUSTOM_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties'
const FMTID = '{D5CDD505-2E9C-101B-9397-08002B2CF9AE}'
const PROPERTY_NAME = 'AIGC'
const CUSTOM_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/custom-properties'
const VT_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes'

const SKIP_DIRS = new Set(['node_modules', '.git', '.svn', '__MACOSX'])

// ---------------------------------------------------------------- CRC32 / ZIP

const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    t[i] = c >>> 0
  }
  return t
})()

function crc32(buf) {
  let c = 0xffffffff
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

function readZipBuffer(buf) {
  const maxBack = Math.min(buf.length, 66 * 1024)
  let eocd = -1
  for (let i = buf.length - 22; i >= buf.length - maxBack && i >= 0; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i
      break
    }
  }
  if (eocd < 0) throw new Error('不是可识别的 ZIP：找不到中央目录')

  const total = buf.readUInt16LE(eocd + 10)
  let cdOffset = buf.readUInt32LE(eocd + 16)
  if (cdOffset === 0xffffffff) throw new Error('不支持 Zip64 的 OOXML 包')

  const entries = []
  let p = cdOffset
  for (let i = 0; i < total; i++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) break
    const flags = buf.readUInt16LE(p + 8)
    const method = buf.readUInt16LE(p + 10)
    const time = buf.readUInt16LE(p + 12)
    const date = buf.readUInt16LE(p + 14)
    const crc = buf.readUInt32LE(p + 16)
    const compSize = buf.readUInt32LE(p + 20)
    const uncompSize = buf.readUInt32LE(p + 24)
    const nameLen = buf.readUInt16LE(p + 28)
    const extraLen = buf.readUInt16LE(p + 30)
    const commentLen = buf.readUInt16LE(p + 32)
    const localOffset = buf.readUInt32LE(p + 42)
    const rawName = buf.subarray(p + 46, p + 46 + nameLen)
    const name = (flags & 0x0800 ? rawName.toString('utf8') : new TextDecoder('utf-8').decode(rawName)).replace(/\\/g, '/')
    entries.push({ name, method, time, date, crc, compSize, uncompSize, localOffset })
    p += 46 + nameLen + extraLen + commentLen
  }
  return { buf, entries }
}

function readEntryData(buf, entry) {
  const lfh = entry.localOffset
  if (lfh + 30 > buf.length || buf.readUInt32LE(lfh) !== 0x04034b50) {
    throw new Error(`本地文件头损坏：${entry.name}`)
  }
  const nameLen = buf.readUInt16LE(lfh + 26)
  const extraLen = buf.readUInt16LE(lfh + 28)
  const start = lfh + 30 + nameLen + extraLen
  const raw = buf.subarray(start, start + entry.compSize)
  if (entry.method === 0) return Buffer.from(raw)
  if (entry.method === 8) return zlib.inflateRawSync(raw)
  throw new Error(`不支持的压缩方法 ${entry.method}：${entry.name}`)
}

function writeZip(entries) {
  const parts = []
  const central = []
  let offset = 0

  for (const e of entries) {
    const nameBuf = Buffer.from(e.name, 'utf8')
    const data = e.data ?? Buffer.alloc(0)
    const method = data.length === 0 ? 0 : 8
    const comp = method === 8 ? zlib.deflateRawSync(data, { level: 6 }) : data
    const crc = crc32(data)
    const flags = 0x0800
    const time = e.time ?? 0
    const date = e.date ?? 0x21

    const lfh = Buffer.alloc(30)
    lfh.writeUInt32LE(0x04034b50, 0)
    lfh.writeUInt16LE(20, 4)
    lfh.writeUInt16LE(flags, 6)
    lfh.writeUInt16LE(method, 8)
    lfh.writeUInt16LE(time, 10)
    lfh.writeUInt16LE(date, 12)
    lfh.writeUInt32LE(crc, 14)
    lfh.writeUInt32LE(comp.length, 18)
    lfh.writeUInt32LE(data.length, 22)
    lfh.writeUInt16LE(nameBuf.length, 26)
    lfh.writeUInt16LE(0, 28)

    parts.push(lfh, nameBuf, comp)
    central.push({ nameBuf, method, time, date, crc, compSize: comp.length, uncompSize: data.length, offset })
    offset += 30 + nameBuf.length + comp.length
  }

  const cdStart = offset
  for (const c of central) {
    const h = Buffer.alloc(46)
    h.writeUInt32LE(0x02014b50, 0)
    h.writeUInt16LE(20, 4)
    h.writeUInt16LE(20, 6)
    h.writeUInt16LE(0x0800, 8)
    h.writeUInt16LE(c.method, 10)
    h.writeUInt16LE(c.time, 12)
    h.writeUInt16LE(c.date, 14)
    h.writeUInt32LE(c.crc, 16)
    h.writeUInt32LE(c.compSize, 20)
    h.writeUInt32LE(c.uncompSize, 24)
    h.writeUInt16LE(c.nameBuf.length, 28)
    h.writeUInt16LE(0, 30)
    h.writeUInt16LE(0, 32)
    h.writeUInt16LE(0, 34)
    h.writeUInt16LE(0, 36)
    h.writeUInt32LE(0, 38)
    h.writeUInt32LE(c.offset, 42)
    parts.push(h, c.nameBuf)
    offset += 46 + c.nameBuf.length
  }

  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(0, 4)
  eocd.writeUInt16LE(0, 6)
  eocd.writeUInt16LE(central.length, 8)
  eocd.writeUInt16LE(central.length, 10)
  eocd.writeUInt32LE(offset - cdStart, 12)
  eocd.writeUInt32LE(cdStart, 16)
  eocd.writeUInt16LE(0, 20)
  parts.push(eocd)

  return Buffer.concat(parts)
}

// ---------------------------------------------------------------- XML 改写

function escapeXml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

function unescapeXml(s) {
  return String(s)
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&')
}

function newCustomXml(payload, prefix = '', vtPrefix = 'vt') {
  const p = prefix ? `${prefix}:` : ''
  return (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n' +
    `<${p}Properties xmlns${prefix ? ':' + prefix : ''}="${CUSTOM_NS}" xmlns:${vtPrefix}="${VT_NS}">` +
    `<${p}property fmtid="${FMTID}" pid="2" name="${PROPERTY_NAME}">` +
    `<${vtPrefix}:lpwstr>${escapeXml(payload)}</${vtPrefix}:lpwstr>` +
    `</${p}property></${p}Properties>`
  )
}

// 在既有 custom.xml 上写入/替换 AIGC 属性，不碰其他自定义属性
function upsertCustomXml(existing, payload) {
  if (!existing) return newCustomXml(payload)

  const text = existing.toString('utf8')
  const rootMatch = text.match(/<([A-Za-z0-9_]+:)?Properties[\s>]/)
  if (!rootMatch) throw new Error('custom.xml 结构无法识别')
  const prefix = rootMatch[1] ? rootMatch[1].slice(0, -1) : ''
  const p = prefix ? `${prefix}:` : ''
  const vtMatch = text.match(/xmlns:([A-Za-z0-9_]+)="[^"]*docPropsVTypes"/)
  const vtPrefix = vtMatch ? vtMatch[1] : 'vt'

  // 去掉同名的旧属性（自闭合与成对两种写法）
  let out = text.replace(
    new RegExp(`<${p}property\\b[^>]*name="${PROPERTY_NAME}"[^>]*/>`, 'g'),
    '',
  )
  out = out.replace(
    new RegExp(`<${p}property\\b[^>]*name="${PROPERTY_NAME}"[^>]*>[\\s\\S]*?</${p}property>`, 'g'),
    '',
  )

  const pids = [...out.matchAll(/\bpid="(\d+)"/g)].map((m) => Number(m[1]))
  const pid = Math.max(1, ...pids) + 1

  const prop =
    `<${p}property fmtid="${FMTID}" pid="${pid}" name="${PROPERTY_NAME}">` +
    `<${vtPrefix}:lpwstr>${escapeXml(payload)}</${vtPrefix}:lpwstr>` +
    `</${p}property>`

  const closeMatch = out.match(new RegExp(`</${p}Properties>`))
  if (!closeMatch) throw new Error('custom.xml 缺少 </Properties>')
  return out.replace(closeMatch[0], prop + closeMatch[0])
}

function ensureContentType(xml) {
  const text = xml.toString('utf8')
  if (text.includes(`PartName="/${CUSTOM_PART}"`)) return xml
  const override = `<Override PartName="/${CUSTOM_PART}" ContentType="${CUSTOM_CT}"/>`
  if (!text.includes('</Types>')) return xml
  return Buffer.from(text.replace('</Types>', override + '</Types>'), 'utf8')
}

function ensureRels(xml) {
  const text = xml.toString('utf8')
  if (/Target="\/?docProps\/custom\.xml"/.test(text)) return xml
  const ids = new Set([...text.matchAll(/\bId="([^"]+)"/g)].map((m) => m[1]))
  let n = 1
  while (ids.has(`rId${n}`)) n++
  const rel = `<Relationship Id="rId${n}" Type="${CUSTOM_REL}" Target="${CUSTOM_PART}"/>`
  if (!text.includes('</Relationships>')) return xml
  return Buffer.from(text.replace('</Relationships>', rel + '</Relationships>'), 'utf8')
}

// ---------------------------------------------------------------- 标识逻辑

export function buildPayload({ producer, produceId, label = '1' }) {
  // 字段集合与顺序按规范；ContentPropagator/PropagateID 在生产者角色下镜像生产者。
  // ReservedCode1/2 留空即不写入 JSON（空值省略规则）。
  const pid = produceId || crypto.randomBytes(16).toString('hex')
  const fields = [
    ['Label', label],
    ['ContentProducer', producer],
    ['ProduceID', pid],
    ['ContentPropagator', producer],
    ['PropagateID', pid],
  ]
  return JSON.stringify(Object.fromEntries(fields.filter(([, v]) => v !== '')))
}

function readLabel(names, read) {
  if (!names.includes(CUSTOM_PART)) return { label: null, reason: 'no custom.xml' }
  let xml
  try {
    xml = read(CUSTOM_PART).toString('utf8')
  } catch (e) {
    return { label: null, reason: `读不到 custom.xml：${e.message}` }
  }
  const m = xml.match(
    new RegExp(`<(?:[A-Za-z0-9_]+:)?property\\b[^>]*name="${PROPERTY_NAME}"[^>]*>([\\s\\S]*?)</(?:[A-Za-z0-9_]+:)?property>`),
  )
  if (!m) return { label: null, reason: 'custom.xml 里没有 AIGC 属性' }
  const inner = m[1]
  const vt = inner.match(/<(?:[A-Za-z0-9_]+:)?lpwstr[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_]+:)?lpwstr>/)
  if (!vt) return { label: null, reason: 'AIGC 属性不是字符串类型' }
  return { label: unescapeXml(vt[1]), reason: null }
}

function inspectLabel(label) {
  if (!label) return { complete: false, missing: ['Label', 'ContentProducer', 'ProduceID'], parsed: null }
  let data
  try {
    data = JSON.parse(label)
  } catch {
    return { complete: false, missing: ['(不是合法 JSON)'], parsed: null }
  }
  const required = ['Label', 'ContentProducer', 'ProduceID']
  const missing = required.filter((k) => !data[k])
  return { complete: missing.length === 0, missing, parsed: data }
}

function loadPackage(file) {
  const buf = fs.readFileSync(file)
  const { entries } = readZipBuffer(buf)
  const map = new Map()
  for (const e of entries) {
    if (e.name.endsWith('/')) continue
    map.set(e.name, readEntryData(buf, e))
  }
  return { entries, map }
}

function stampPackage(file, payload) {
  const { entries, map } = loadPackage(file)
  const next = new Map(map)

  const existing = map.get(CUSTOM_PART)
  next.set(CUSTOM_PART, Buffer.from(upsertCustomXml(existing, payload), 'utf8'))

  const ct = map.get('[Content_Types].xml')
  if (ct) next.set('[Content_Types].xml', ensureContentType(ct))

  const rels = map.get('_rels/.rels')
  if (rels) next.set('_rels/.rels', ensureRels(rels))

  // 保持原顺序，新部件追加在末尾
  const order = entries.map((e) => e.name)
  const rebuilt = []
  for (const name of order) {
    if (!next.has(name)) continue
    const meta = entries.find((e) => e.name === name)
    rebuilt.push({ name, data: next.get(name), time: meta?.time, date: meta?.date })
  }
  for (const [name, data] of next) {
    if (!order.includes(name)) rebuilt.push({ name, data })
  }

  const out = writeZip(rebuilt)
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.aigc-tmp`)
  fs.writeFileSync(tmp, out)
  fs.renameSync(tmp, file)
}

// ---------------------------------------------------------------- 遍历

function walk(root, extensions) {
  const out = []
  const visited = new Set()
  const visit = (dir) => {
    let real
    try {
      real = fs.realpathSync(dir)
    } catch {
      return
    }
    if (visited.has(real)) return
    visited.add(real)
    let entries
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue
      const full = path.join(dir, e.name)
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue
        visit(full)
        continue
      }
      if (extensions.includes(path.extname(e.name).toLowerCase())) out.push(full)
    }
  }
  visit(root)
  return out.sort()
}

function resolveInput(raw) {
  if (!raw) return { error: 'ERROR: path is required.' }
  const p = path.resolve(String(raw).replace(/^~/, process.env.USERPROFILE ?? ''))
  if (!fs.existsSync(p)) return { error: `ERROR: 路径不存在: ${p}` }
  return { p, isFile: fs.statSync(p).isFile() }
}

function fmtSize(n) {
  if (n < 1024) return `${n} B`
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1048576).toFixed(1)} MB`
}

// ---------------------------------------------------------------- 工具

function registerCheck(ctx, config) {
  ctx.tools.register(
    defineTool({
      name: 'aigc_label_check',
      description:
        'Check Office files for the AIGC implicit label required for AI-generated content: reads the ' +
        'docProps/custom.xml AIGC property from each docx/xlsx/pptx and reports whether the label is ' +
        'present and whether its producer fields are complete. Reports what it can and cannot verify ' +
        'instead of assuming the label is valid.',
      parameters: {
        path: {
          type: 'string',
          required: true,
          description: '文件或目录。目录会递归查找 docx/xlsx/pptx。',
        },
      },
      output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
      async execute(args) {
        const input = resolveInput(args.path)
        if (input.error) return input.error
        const exts = config.extensions ?? ['.docx', '.xlsx', '.pptx']
        const files = input.isFile ? [input.p] : walk(input.p, exts)
        if (files.length === 0) return `没找到 ${exts.join(' / ')} 文件：${input.p}`

        const rows = []
        let labeled = 0
        let partial = 0
        let clean = 0
        let broken = 0

        for (const file of files) {
          const rel = input.isFile ? path.basename(file) : path.relative(input.p, file).split(path.sep).join('/')
          let pkg
          try {
            pkg = loadPackage(file)
          } catch (e) {
            rows.push(`  ✗ ${rel} — 不是可读的 OOXML 包（${e.message}）`)
            broken++
            continue
          }
          const { label } = readLabel([...pkg.map.keys()], (n) => pkg.map.get(n))
          const info = inspectLabel(label)
          if (info.complete) {
            labeled++
            rows.push(`  ✓ ${rel} — ${info.parsed.ContentProducer} · ${info.parsed.ProduceID}`)
          } else if (label) {
            partial++
            rows.push(`  ~ ${rel} — 有标识但缺字段：${info.missing.join(', ')}`)
          } else {
            clean++
          }
        }

        const lines = []
        lines.push(`aigc_label_check ${input.p}`)
        lines.push(`${files.length} 个 OOXML 文件 · 带完整标识 ${labeled} · 不完整 ${partial} · 无标识 ${clean}${broken ? ` · 读不了 ${broken}` : ''}`)
        lines.push('')
        if (labeled + partial + broken > 0) {
          lines.push('## 明细')
          for (const r of rows) lines.push(r)
          lines.push('')
        }
        if (clean > 0 && labeled + partial < files.length) {
          lines.push(`## 没有标识的 ${clean} 个`)
          lines.push('  未逐条列出；需要清单就去掉已打标的文件再查一次，或直接看目录。')
          lines.push('')
        }
        lines.push('## 判定口径')
        lines.push('  完整 = Label + ContentProducer + ProduceID 三项非空。')
        lines.push('  ReservedCode1/2 不算缺项：官方算法要接入单发放的私钥，本地链路算不出可验签的值，')
        lines.push('  留空比填一个本地随机值更诚实。若检测侧按四项判，本地产物会被判为不完整。')
        return lines.join('\n')
      },
    }),
  )
}

function registerWrite(ctx, config) {
  ctx.tools.register(
    defineTool({
      name: 'aigc_label_write',
      description:
        "Write the AIGC implicit label into Office files' docProps/custom.xml, then read it back to " +
        'confirm. Requires the 27-character content-producer code from your filing: it is deliberately ' +
        'not built in, because writing someone else\'s code into a file misattributes its origin. ' +
        'Supports a dry run that reports what would change without touching anything.',
      parameters: {
        path: {
          type: 'string',
          required: true,
          description: '文件或目录。目录会递归处理 docx/xlsx/pptx。',
        },
        producer: {
          type: 'string',
          description: '生成合成服务提供者编码（27 位）。不给就用配置里的 contentProducer。',
        },
        produceId: {
          type: 'string',
          description: '内容制作编号，缺省随机生成 32 位十六进制。',
        },
        label: {
          type: 'string',
          description: '标识取值 1/2/3，缺省用配置。',
        },
        dryRun: {
          type: 'boolean',
          description: '只报告将要写入的内容，不改文件。',
        },
      },
      output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
      async execute(args) {
        const input = resolveInput(args.path)
        if (input.error) return input.error

        const producer = String(args.producer ?? config.contentProducer ?? '').trim()
        if (!producer) {
          return [
            'ERROR: 没有服务提供者编码，拒绝写入。',
            '',
            'ContentProducer 是接入方在备案链路里拿到的 27 位编码，不是一个可以随便填的常量。',
            '写错编码等于把这份文件的来源指向了别的主体，比不写标识更糟。',
            '',
            '用法：aigc_label_write({ path, producer: "<你的 27 位编码>" })',
          ].join('\n')
        }
        if (producer.length !== 27) {
          return `ERROR: 编码长度是 ${producer.length}，规范要求 27 位。请核对接入单。`
        }

        const label = String(args.label ?? config.label ?? '1')
        if (!['1', '2', '3'].includes(label)) return 'ERROR: label 只能是 1（属于）、2（可能为）、3（疑似为）。'

        const produceId = args.produceId ? String(args.produceId) : crypto.randomBytes(16).toString('hex')
        const payload = buildPayload({ producer, produceId, label })

        const exts = config.extensions ?? ['.docx', '.xlsx', '.pptx']
        const files = input.isFile ? [input.p] : walk(input.p, exts)
        if (files.length === 0) return `没找到 ${exts.join(' / ')} 文件：${input.p}`

        const lines = [`aigc_label_write ${input.p}`]
        lines.push(`payload: ${payload}`)
        if (args.dryRun) {
          lines.push('')
          lines.push(`dry run：将处理 ${files.length} 个文件，未改动任何内容。`)
          for (const f of files.slice(0, 30)) lines.push(`  ${input.isFile ? path.basename(f) : path.relative(input.p, f)}`)
          if (files.length > 30) lines.push(`  … 另 ${files.length - 30} 个`)
          return lines.join('\n')
        }

        let done = 0
        const failures = []
        for (const file of files) {
          const rel = input.isFile ? path.basename(file) : path.relative(input.p, file).split(path.sep).join('/')
          try {
            stampPackage(file, payload)
            // 读回校验：写完必须能原样读出来
            const back = loadPackage(file)
            const { label: written } = readLabel([...back.map.keys()], (n) => back.map.get(n))
            if (written !== payload) {
              failures.push(`${rel} — 读回不一致：${written ?? '(空)'}`)
              continue
            }
            done++
          } catch (e) {
            failures.push(`${rel} — ${e.message}`)
          }
        }

        lines.push('')
        lines.push(`已写入 ${done} 个${failures.length ? `，失败 ${failures.length} 个` : ''}`)
        for (const f of failures) lines.push(`  ✗ ${f}`)
        lines.push('')
        lines.push('## 还要人工确认的')
        lines.push('  · 显式标识：按规范，面向用户的界面或内容本身还要有可见提示，隐式标识不替代它')
        lines.push('  · 编码是否是你这条链路该用的那个（云端与本地包各一个，不通用）')
        lines.push('  · 真实检测侧是否认这份标识（本地算不出可验签的 ReservedCode）')
        return lines.join('\n')
      },
    }),
  )
}

export function apply(ctx, config) {
  registerCheck(ctx, config)
  registerWrite(ctx, config)
}
