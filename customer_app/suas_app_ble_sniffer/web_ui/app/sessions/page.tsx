"use client";

import { useLiveQuery } from "dexie-react-hooks";
import { db } from "@/lib/db";
import { SiteHeader } from "@/components/site-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Trash2, Eye } from "lucide-react";
import Link from "next/link";

export default function SessionsPage() {
  const sessions = useLiveQuery(() => db.sessions.reverse().toArray());

  const deleteSession = async (id: number) => {
    if (confirm("Are you sure you want to delete this session?")) {
        await db.sessions.delete(id);
        await db.packets.where({ sessionId: id }).delete();
    }
  };

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <SiteHeader />
      <main className="container mx-auto p-4">
        <h1 className="text-2xl font-bold mb-4">Recorded Sessions</h1>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {sessions?.map(session => (
                <Card key={session.id}>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">
                            {session.name}
                        </CardTitle>
                        <div className="flex gap-2">
                            <Link href={`/sessions/${session.id}`}>
                                <Button variant="ghost" size="icon">
                                    <Eye className="h-4 w-4" />
                                </Button>
                            </Link>
                            <Button variant="ghost" size="icon" onClick={() => deleteSession(session.id!)}>
                                <Trash2 className="h-4 w-4 text-red-500" />
                            </Button>
                        </div>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{session.packetCount} Packets</div>
                        <p className="text-xs text-muted-foreground">
                            Started: {new Date(session.startTime).toLocaleString()}
                        </p>
                        {session.endTime && (
                            <p className="text-xs text-muted-foreground">
                                Duration: {((session.endTime - session.startTime) / 1000).toFixed(1)}s
                            </p>
                        )}
                    </CardContent>
                </Card>
            ))}
            {sessions?.length === 0 && <p className="col-span-full text-center text-muted-foreground">No recorded sessions found. Start a recording from the dashboard.</p>}
        </div>
      </main>
    </div>
  );
}
