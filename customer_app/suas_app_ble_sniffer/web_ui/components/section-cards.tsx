import { IconTrendingDown, IconTrendingUp } from "@tabler/icons-react";

import { Badge } from "@/components/ui/badge";
import {
	Card,
	CardAction,
	CardDescription,
	CardFooter,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";

interface SectionCardsProps {
	totalPackets: number;
	deviceCount: number;
	packetRate: number;
	isConnected: boolean;
}

export function SectionCards({
	totalPackets,
	deviceCount,
	packetRate,
	isConnected,
}: SectionCardsProps) {
	return (
		<div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
			<Card className="@container/card">
				<CardHeader>
					<CardDescription>Status</CardDescription>
					<CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
						{isConnected ? "Connected" : "Disconnected"}
					</CardTitle>
					<CardAction>
						<Badge variant={isConnected ? "default" : "destructive"}>
							{isConnected ? "Active" : "Offline"}
						</Badge>
					</CardAction>
				</CardHeader>
				<CardFooter className="flex-col items-start gap-1.5 text-sm">
					<div className="line-clamp-1 flex gap-2 font-medium">
						WS Connection
					</div>
				</CardFooter>
			</Card>
			<Card className="@container/card">
				<CardHeader>
					<CardDescription>Total Packets</CardDescription>
					<CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
						{totalPackets.toLocaleString()}
					</CardTitle>
				</CardHeader>
				<CardFooter className="flex-col items-start gap-1.5 text-sm">
					<div className="text-muted-foreground">
						Packets captured this session
					</div>
				</CardFooter>
			</Card>
			<Card className="@container/card">
				<CardHeader>
					<CardDescription>Devices Found</CardDescription>
					<CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
						{deviceCount}
					</CardTitle>
				</CardHeader>
				<CardFooter className="flex-col items-start gap-1.5 text-sm">
					<div className="text-muted-foreground">Unique MAC addresses</div>
				</CardFooter>
			</Card>
			<Card className="@container/card">
				<CardHeader>
					<CardDescription>Packet Rate</CardDescription>
					<CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
						{packetRate.toFixed(1)}/s
					</CardTitle>
				</CardHeader>
				<CardFooter className="flex-col items-start gap-1.5 text-sm">
					<div className="text-muted-foreground">Current traffic</div>
				</CardFooter>
			</Card>
		</div>
	);
}
