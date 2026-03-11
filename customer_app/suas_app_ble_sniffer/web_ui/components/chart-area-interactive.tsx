"use client";

import * as React from "react";
import { Area, AreaChart, CartesianGrid, XAxis } from "recharts";

import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import {
	ChartContainer,
	ChartTooltip,
	ChartTooltipContent,
	type ChartConfig,
} from "@/components/ui/chart";

export const description = "A realtime area chart";

const chartConfig = {
	stats: {
		label: "Stats",
	},
	packetRate: {
		label: "Packet Rate (pps)",
		color: "hsl(var(--chart-1))",
	},
	activeDevices: {
		label: "Active Devices",
		color: "hsl(var(--chart-2))",
	},
} satisfies ChartConfig;

interface ChartAreaInteractiveProps {
	data: {
		time: string;
		packetRate: number;
		activeDevices: number;
	}[];
}

export function ChartAreaInteractive({ data }: ChartAreaInteractiveProps) {
	return (
		<Card className="@container/card">
			<CardHeader>
				<CardTitle>Realtime Traffic</CardTitle>
				<CardDescription>
					Packet rate and active devices over last 60 seconds
				</CardDescription>
			</CardHeader>
			<CardContent className="px-2 pt-4 sm:px-6 sm:pt-6">
				{data.length === 0 ? (
					<div className="flex h-[250px] w-full items-center justify-center text-muted-foreground">
						Waiting for data...
					</div>
				) : (
					<ChartContainer
						config={chartConfig}
						className="aspect-auto h-[250px] w-full"
					>
						<AreaChart data={data}>
							<defs>
								<linearGradient id="fillPacketRate" x1="0" y1="0" x2="0" y2="1">
									<stop
										offset="5%"
										stopColor="var(--color-packetRate)"
										stopOpacity={0.8}
									/>
									<stop
										offset="95%"
										stopColor="var(--color-packetRate)"
										stopOpacity={0.1}
									/>
								</linearGradient>
								<linearGradient
									id="fillActiveDevices"
									x1="0"
									y1="0"
									x2="0"
									y2="1"
								>
									<stop
										offset="5%"
										stopColor="var(--color-activeDevices)"
										stopOpacity={0.8}
									/>
									<stop
										offset="95%"
										stopColor="var(--color-activeDevices)"
										stopOpacity={0.1}
									/>
								</linearGradient>
							</defs>
							<CartesianGrid vertical={false} />
							<XAxis
								dataKey="time"
								tickLine={false}
								axisLine={false}
								tickMargin={8}
								minTickGap={32}
								tickFormatter={(value) => {
									const date = new Date(value);
									return date.toLocaleTimeString("en-US", {
										minute: "2-digit",
										second: "2-digit",
									});
								}}
							/>
							<ChartTooltip
								cursor={false}
								content={
									<ChartTooltipContent
										labelFormatter={(value) => {
											return new Date(value).toLocaleTimeString("en-US", {
												hour: "2-digit",
												minute: "2-digit",
												second: "2-digit",
											});
										}}
										indicator="dot"
									/>
								}
							/>
							<Area
								dataKey="activeDevices"
								type="natural"
								fill="url(#fillActiveDevices)"
								stroke="var(--color-activeDevices)"
								stackId="a"
							/>
							<Area
								dataKey="packetRate"
								type="natural"
								fill="url(#fillPacketRate)"
								stroke="var(--color-packetRate)"
								stackId="a"
							/>
						</AreaChart>
					</ChartContainer>
				)}
			</CardContent>
		</Card>
	);
}
