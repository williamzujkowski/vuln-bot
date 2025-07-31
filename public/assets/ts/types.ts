// Re-export vulnerability types
export * from "./types/vulnerability";

// Analytics types
export interface AnalyticsConfig {
  enabled: boolean;
  storageKey: string;
  maxEvents: number;
  flushInterval: number;
  endpoint?: string;
}

// Dashboard types
export interface DashboardConfig {
  apiEndpoint: string;
  defaultPageSize: number;
  searchKeys: string[];
  severityOrder: string[];
}
