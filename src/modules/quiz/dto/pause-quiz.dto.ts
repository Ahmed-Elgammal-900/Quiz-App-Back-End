import { IsInt, Min, IsNotEmpty, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class PauseQuizDto {
  @ApiProperty({
    description: 'Index of the question the user paused on',
    example: 3,
  })
  @IsInt()
  @Min(0)
  @IsOptional()
  pausedAtQuestionIndex?: number;

  @ApiProperty({
    description: 'Remaining time in seconds when the quiz was paused',
    example: 120,
    minimum: 0,
  })
  @IsInt()
  @Min(0)
  @IsNotEmpty()
  remainingTimeSeconds!: number;
}
