import React, { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface BentoGridProps {
  children: ReactNode;
  className?: string;
  cols?: 2 | 3 | 4 | 6 | 12;
}

export function BentoGrid({
  children,
  className,
  cols = 12,
}: BentoGridProps) {
  const colClasses = {
    2: "grid-cols-1 md:grid-cols-2",
    3: "grid-cols-1 md:grid-cols-2 lg:grid-cols-3",
    4: "grid-cols-1 sm:grid-cols-2 lg:grid-cols-4",
    6: "grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6",
    12: "grid-cols-1 sm:grid-cols-2 md:grid-cols-6 lg:grid-cols-12",
  }[cols];

  return (
    <div className={cn("grid gap-5", colClasses, className)}>
      {children}
    </div>
  );
}

