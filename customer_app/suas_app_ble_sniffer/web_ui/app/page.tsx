"use client";

import { ChartAreaInteractive } from "@/components/chart-area-interactive";
import { DataTable } from "@/components/data-table";
import { SectionCards } from "@/components/section-cards";
import { SiteHeader } from "@/components/site-header";
import { useSniffer } from "@/hooks/use-sniffer";
import { Button } from "@/components/ui/button";
import { CircleIcon } from "lucide-react";

export default function Page() {
	const { devices, isConnected, stats, history, isRecording, startRecording, stopRecording } = useSniffer();

	return (
		<div className="flex min-h-screen flex-col bg-background">
			<SiteHeader />
			<main className="flex flex-1 flex-col">
				<div className="container mx-auto flex flex-1 flex-col gap-2 px-4 lg:px-6">
					<div className="flex flex-col gap-4 py-4 md:gap-6 md:py-6">
						<div className="flex items-center justify-between">
							<h2 className="text-lg font-semibold">Live Dashboard</h2>
							<Button 
								variant={isRecording ? "destructive" : "default"} 
								onClick={isRecording ? stopRecording : startRecording}
								className="gap-2"
							>
								{isRecording ? (
									<>
										<CircleIcon className="h-4 w-4 fill-current animate-pulse" />
										Stop Recording
									</>
								) : (
									<>
										<CircleIcon className="h-4 w-4" />
										Start Recording
									</>
								)}
							</Button>
						</div>
						<SectionCards
							totalPackets={stats.totalPackets}
							deviceCount={devices.length}
							packetRate={stats.packetRate}
							isConnected={isConnected}
						/>
						<ChartAreaInteractive data={history} />
						<DataTable data={devices} />
					</div>
				</div>
			</main>
		</div>
	);
}
