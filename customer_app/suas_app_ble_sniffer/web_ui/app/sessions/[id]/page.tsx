"use client";

import { useLiveQuery } from "dexie-react-hooks";
import { db } from "@/lib/db";
import { SiteHeader } from "@/components/site-header";
import { useParams } from "next/navigation";
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { useState } from "react";
import { Packet } from "@/lib/db";

export default function SessionDetailsPage() {
	const params = useParams();
	const id = Number(params.id);
	const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);

	const session = useLiveQuery(() => db.sessions.get(id), [id]);
	const packets = useLiveQuery(
		() => db.packets.where("sessionId").equals(id).toArray(),
		[id]
	);

	if (!session)
		return (
			<div className="flex min-h-screen flex-col bg-background">
				<SiteHeader />
				<main className="container mx-auto p-4">Loading...</main>
			</div>
		);

	return (
		<div className="flex min-h-screen flex-col bg-background">
			<SiteHeader />
			<main className="container mx-auto p-4 space-y-4">
				<div className="flex items-center gap-4">
					<Link href="/sessions">
						<Button variant="outline" size="icon">
							<ArrowLeft className="h-4 w-4" />
						</Button>
					</Link>
					<h1 className="text-2xl font-bold">{session.name}</h1>
				</div>

				<Card>
					<CardHeader>
						<CardTitle>Session Details</CardTitle>
					</CardHeader>
					<CardContent>
						<div className="grid grid-cols-2 md:grid-cols-4 gap-4">
							<div>
								<div className="text-sm text-muted-foreground">Start Time</div>
								<div className="font-medium">
									{new Date(session.startTime).toLocaleString()}
								</div>
							</div>
							<div>
								<div className="text-sm text-muted-foreground">End Time</div>
								<div className="font-medium">
									{session.endTime
										? new Date(session.endTime).toLocaleString()
										: "Ongoing"}
								</div>
							</div>
							<div>
								<div className="text-sm text-muted-foreground">Packets</div>
								<div className="font-medium">{packets?.length || 0}</div>
							</div>
							<div>
								<div className="text-sm text-muted-foreground">Devices</div>
								<div className="font-medium">{session.deviceCount}</div>
							</div>
						</div>
					</CardContent>
				</Card>

				<Card>
					<CardHeader>
						<CardTitle>Packet Log</CardTitle>
					</CardHeader>
					<CardContent>
						<div className="rounded-md border">
							<Table>
								<TableHeader>
									<TableRow>
										<TableHead>Time</TableHead>
										<TableHead>MAC</TableHead>
										<TableHead>RSSI</TableHead>
										<TableHead>Name</TableHead>
										<TableHead>Type</TableHead>
										<TableHead>Data</TableHead>
									</TableRow>
								</TableHeader>
								<TableBody>
									{packets?.slice(0, 500).map((packet) => (
										<TableRow
											key={packet.id}
											className="cursor-pointer hover:bg-muted/50"
											onClick={() => setSelectedPacket(packet)}
										>
											<TableCell>
												{new Date(packet.timestamp).toLocaleTimeString()}.
												{String(packet.timestamp % 1000).padStart(3, "0")}
											</TableCell>
											<TableCell className="font-mono">{packet.mac}</TableCell>
											<TableCell>{packet.rssi}</TableCell>
											<TableCell>{packet.name || "-"}</TableCell>
											<TableCell>{packet.type || "-"}</TableCell>
											<TableCell
												className="font-mono text-xs max-w-xs truncate"
												title={JSON.stringify(packet.raw)}
											>
												{packet.raw?.mfg_data_hex || JSON.stringify(packet.raw)}
											</TableCell>
										</TableRow>
									))}
									{packets && packets.length > 500 && (
										<TableRow>
											<TableCell
												colSpan={6}
												className="text-center text-muted-foreground py-4"
											>
												Showing first 500 of {packets.length} packets.
											</TableCell>
										</TableRow>
									)}
									{packets && packets.length === 0 && (
										<TableRow>
											<TableCell
												colSpan={6}
												className="text-center text-muted-foreground py-4"
											>
												No packets recorded.
											</TableCell>
										</TableRow>
									)}
								</TableBody>
							</Table>
						</div>
					</CardContent>
				</Card>

				<Dialog
					open={!!selectedPacket}
					onOpenChange={(open) => !open && setSelectedPacket(null)}
				>
					<DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
						<DialogHeader>
							<DialogTitle>Packet Details</DialogTitle>
							<DialogDescription>
								Received at{" "}
								{selectedPacket &&
									new Date(selectedPacket.timestamp).toLocaleString()}
							</DialogDescription>
						</DialogHeader>
						{selectedPacket && (
							<div className="grid gap-4 py-4">
								<div className="grid grid-cols-2 gap-4">
									<div>
										<div className="text-sm font-medium text-muted-foreground">
											MAC Address
										</div>
										<div>{selectedPacket.mac}</div>
									</div>
									<div>
										<div className="text-sm font-medium text-muted-foreground">
											RSSI
										</div>
										<div>{selectedPacket.rssi} dBm</div>
									</div>
									<div>
										<div className="text-sm font-medium text-muted-foreground">
											Type
										</div>
										<div>{selectedPacket.type || "N/A"}</div>
									</div>
									<div>
										<div className="text-sm font-medium text-muted-foreground">
											Device Name
										</div>
										<div>{selectedPacket.name || "N/A"}</div>
									</div>
								</div>
								<div>
									<div className="text-sm font-medium text-muted-foreground mb-2">
										Raw Data (JSON)
									</div>
									<div className="rounded-md bg-muted p-4 overflow-auto">
										<pre className="text-xs font-mono whitespace-pre-wrap break-all">
											{JSON.stringify(selectedPacket.raw, null, 2)}
										</pre>
									</div>
								</div>
								{(selectedPacket.raw?.mfg_data ||
									selectedPacket.raw?.payload) && (
									<div>
										<div className="text-sm font-medium text-muted-foreground mb-2">
											Decoded Data
										</div>
										<div className="rounded-md bg-muted p-4 space-y-4">
											{selectedPacket.raw?.mfg_data && (
												<div>
													<div className="text-xs font-medium text-muted-foreground mb-1">
														Manufacturer Data
													</div>
													<div className="grid gap-2">
														<div>
															<div className="text-[10px] uppercase text-muted-foreground">
																Hex
															</div>
															<div className="font-mono text-sm break-all">
																{selectedPacket.raw.mfg_data
																	.match(/.{1,2}/g)
																	?.join(" ") || selectedPacket.raw.mfg_data}
															</div>
														</div>
														<div>
															<div className="text-[10px] uppercase text-muted-foreground">
																ASCII
															</div>
															<div className="font-mono text-sm break-all bg-background/50 p-2 rounded border">
																{selectedPacket.raw.mfg_data_ascii || "-"}
															</div>
														</div>
													</div>
												</div>
											)}
											{selectedPacket.raw?.payload && (
												<div>
													<div className="text-xs font-medium text-muted-foreground mb-1">
														Payload
													</div>
													<div className="grid gap-2">
														<div>
															<div className="text-[10px] uppercase text-muted-foreground">
																Hex
															</div>
															<div className="font-mono text-sm break-all">
																{selectedPacket.raw.payload
																	.match(/.{1,2}/g)
																	?.join(" ") || selectedPacket.raw.payload}
															</div>
														</div>
														<div>
															<div className="text-[10px] uppercase text-muted-foreground">
																ASCII
															</div>
															<div className="font-mono text-sm break-all bg-background/50 p-2 rounded border">
																{selectedPacket.raw.payload_ascii || "-"}
															</div>
														</div>
													</div>
												</div>
											)}
										</div>
									</div>
								)}
							</div>
						)}
					</DialogContent>
				</Dialog>
			</main>
		</div>
	);
}
