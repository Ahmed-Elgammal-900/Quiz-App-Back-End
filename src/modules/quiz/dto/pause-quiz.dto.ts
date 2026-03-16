import { IsInt, Min, IsUUID, IsNotEmpty } from 'class-validator';

export class PauseQuizDto {
  @IsUUID()
  @IsNotEmpty()
  pausedAtQuestionId: string;

  @IsInt()
  @Min(0)
  @IsNotEmpty()
  remainingTimeSeconds: number;
}
