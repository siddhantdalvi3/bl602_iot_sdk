import Dexie, { type EntityTable } from 'dexie';

export interface Session {
  id?: number;
  name: string;
  startTime: number;
  endTime?: number;
  deviceCount: number;
  packetCount: number;
}

export interface Packet {
  id?: number;
  sessionId: number;
  timestamp: number;
  mac?: string;
  rssi?: number;
  name?: string;
  manufacturer?: string;
  type?: string;
  raw?: any; 
}

export const db = new Dexie('SnifferDatabase') as Dexie & {
  sessions: EntityTable<Session, 'id'>;
  packets: EntityTable<Packet, 'id'>;
};

db.version(1).stores({
  sessions: '++id, startTime, name',
  packets: '++id, sessionId, timestamp, mac'
});
