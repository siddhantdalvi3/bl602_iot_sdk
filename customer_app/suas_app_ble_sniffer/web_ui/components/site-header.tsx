import { Button } from "@/components/ui/button"
import Link from "next/link"

export function SiteHeader() {
  return (
    <header className="flex h-14 shrink-0 items-center gap-2 border-b px-4 lg:px-6">
      <div className="flex w-full items-center gap-4 lg:gap-6">
        <h1 className="text-base font-medium">BLE Sniffer</h1>
        <nav className="flex items-center gap-4 text-sm font-medium">
            <Link href="/" className="transition-colors hover:text-foreground/80 text-foreground/60">Dashboard</Link>
            <Link href="/sessions" className="transition-colors hover:text-foreground/80 text-foreground/60">Sessions</Link>
        </nav>
        <div className="ml-auto flex items-center gap-2">
          {/* Add actions here if needed */}
        </div>
      </div>
    </header>
  )
}
