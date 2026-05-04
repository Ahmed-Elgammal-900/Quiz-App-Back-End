export interface LeaderboardEntry {
  userId: string;
  name: string;
  totalScore: number;
}

export type UserRank = LeaderboardEntry & { rank: number };
