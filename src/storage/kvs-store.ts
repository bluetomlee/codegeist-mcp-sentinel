import { kvs, WhereConditions } from '@forge/kvs';
import type { ScanStore, ServerRecord } from './store';

const PREFIX = 'server:';

/** Forge KVS-backed store. Keys: `server:<serverId>`. */
export class KvsScanStore implements ScanStore {
  async get(serverId: string): Promise<ServerRecord | undefined> {
    return kvs.get<ServerRecord>(PREFIX + serverId);
  }

  async put(record: ServerRecord): Promise<void> {
    await kvs.set(PREFIX + record.serverId, record);
  }

  async delete(serverId: string): Promise<void> {
    await kvs.delete(PREFIX + serverId);
  }

  async list(): Promise<ServerRecord[]> {
    const out: ServerRecord[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 20; page++) {
      let q = kvs.query().where('key', WhereConditions.beginsWith(PREFIX)).limit(50);
      if (cursor) q = q.cursor(cursor);
      const res = await q.getMany<ServerRecord>();
      out.push(...res.results.map((r) => r.value));
      cursor = res.nextCursor;
      if (!cursor) break;
    }
    return out;
  }
}
