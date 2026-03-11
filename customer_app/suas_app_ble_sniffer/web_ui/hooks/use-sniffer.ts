import { useState, useEffect, useRef, useCallback } from "react";
import { db, Packet } from "../lib/db";

export interface SnifferPacket {
	mac?: string;
	rssi?: number;
	name?: string;
	manufacturer?: string;
	type?: string;
	timestamp: number;
	[key: string]: unknown;
}

export interface SnifferDevice {
	mac: string;
	name: string;
	rssi: number;
	packetCount: number;
	lastSeen: number;
	manufacturer: string;
}

export function useSniffer() {
	const [packets, setPackets] = useState<SnifferPacket[]>([]);
	const [devices, setDevices] = useState<Map<string, SnifferDevice>>(new Map());
	const [isConnected, setIsConnected] = useState(false);
	const [stats, setStats] = useState({ totalPackets: 0, packetRate: 0 });
	const [history, setHistory] = useState<
		{ time: string; packetRate: number; activeDevices: number }[]
	>([]);
	const [isRecording, setIsRecording] = useState(false);

	const wsRef = useRef<WebSocket | null>(null);
	const lastPacketTimeRef = useRef<number>(0);
	const packetCountRef = useRef(0);
	const deviceCountRef = useRef(0);

	// Recording refs to access inside WebSocket callback
	const recordingRef = useRef(false);
	const sessionIdRef = useRef<number | null>(null);
	const packetBufferRef = useRef<Packet[]>([]);
	const sessionPacketCountRef = useRef(0);

	const startRecording = useCallback(async () => {
		try {
			const id = await db.sessions.add({
				name: `Session ${new Date().toLocaleString()}`,
				startTime: Date.now(),
				deviceCount: 0,
				packetCount: 0,
			});
			sessionIdRef.current = id as number;
			recordingRef.current = true;
			sessionPacketCountRef.current = 0;
			packetBufferRef.current = [];
			setIsRecording(true);
			console.log("Started recording session:", id);
		} catch (e) {
			console.error("Failed to start recording:", e);
		}
	}, []);

	const stopRecording = useCallback(async () => {
		recordingRef.current = false;
		setIsRecording(false);

		// Flush buffer
		if (packetBufferRef.current.length > 0 && sessionIdRef.current) {
			await db.packets.bulkAdd(packetBufferRef.current);
			packetBufferRef.current = [];
		}

		if (sessionIdRef.current) {
			await db.sessions.update(sessionIdRef.current, {
				endTime: Date.now(),
				packetCount: sessionPacketCountRef.current,
				deviceCount: devices.size, // Approx
			});
			sessionIdRef.current = null;
		}
		console.log("Stopped recording");
	}, [devices]);

	useEffect(() => {
		lastPacketTimeRef.current = Date.now();
	}, []);

	useEffect(() => {
		const connect = () => {
			// TODO: Move to config
			const ws = new WebSocket("ws://localhost:8765");

			ws.onopen = () => {
				setIsConnected(true);
				console.log("Connected to Sniffer");
			};

			ws.onclose = () => {
				setIsConnected(false);
				console.log("Disconnected from Sniffer");
				// Try to reconnect in a bit...
				setTimeout(connect, 3000);
			};

			ws.onmessage = (event) => {
				try {
					const packet = JSON.parse(event.data);
					packet.timestamp = Date.now(); // Add client-side timestamp

					// Handle recording
					if (recordingRef.current && sessionIdRef.current) {
						packetBufferRef.current.push({
							sessionId: sessionIdRef.current,
							timestamp: packet.timestamp,
							mac: packet.mac,
							rssi: packet.rssi,
							name: packet.name,
							manufacturer: packet.manufacturer,
							type: packet.type,
							raw: packet,
						});
						sessionPacketCountRef.current++;

						// Batch write every 50 packets
						if (packetBufferRef.current.length >= 50) {
							db.packets.bulkAdd(packetBufferRef.current).catch(console.error);
							packetBufferRef.current = [];

							// Update session stats in DB occasionally
							db.sessions.update(sessionIdRef.current, {
								packetCount: sessionPacketCountRef.current,
							});
						}
					}

					setPackets((prev) => {
						const newPackets = [...prev, packet];
						if (newPackets.length > 100) newPackets.shift(); // Keep last 100
						return newPackets;
					});

					setStats((prev) => ({
						...prev,
						totalPackets: prev.totalPackets + 1,
					}));

					if (packet.mac) {
						setDevices((prev) => {
							const newDevices = new Map(prev);
							const existing = newDevices.get(packet.mac) || {
								mac: packet.mac,
								name: packet.name || "Unknown",
								rssi: packet.rssi || 0,
								packetCount: 0,
								lastSeen: 0,
								manufacturer: "Unknown",
							};

							existing.rssi = packet.rssi || existing.rssi;
							existing.packetCount += 1;
							existing.lastSeen = Date.now();
							if (packet.name) existing.name = packet.name;

							newDevices.set(packet.mac, existing);
							return newDevices;
						});
					}

					// Rate calc logic could go here or in a separate interval
					packetCountRef.current++;
				} catch (e) {
					console.error("Error parsing packet", e);
				}
			};

			wsRef.current = ws;
		};

		connect();

		return () => {
			wsRef.current?.close();
		};
	}, []);

	// Keep device count ref in sync
	useEffect(() => {
		deviceCountRef.current = devices.size;
	}, [devices]);

	useEffect(() => {
		const interval = setInterval(() => {
			const now = Date.now();
			const elapsed = (now - lastPacketTimeRef.current) / 1000;
			if (elapsed >= 1) {
				const currentRate = Math.round(packetCountRef.current / elapsed);
				setStats((prev) => ({
					...prev,
					packetRate: currentRate,
				}));

				setHistory((prev) => {
					const newHistory = [
						...prev,
						{
							time: new Date().toISOString(),
							packetRate: currentRate,
							activeDevices: deviceCountRef.current,
						},
					];
					if (newHistory.length > 60) newHistory.shift(); // Keep last 60 seconds
					return newHistory;
				});

				packetCountRef.current = 0;
				lastPacketTimeRef.current = now;
			}
		}, 1000);
		return () => clearInterval(interval);
	}, []);

	return {
		packets,
		devices: Array.from(devices.values()),
		isConnected,
		stats,
		history,
		isRecording,
		startRecording,
		stopRecording,
	};
}
