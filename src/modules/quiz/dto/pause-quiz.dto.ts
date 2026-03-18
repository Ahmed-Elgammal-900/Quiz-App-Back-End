import { IsInt, Min, IsUUID, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class PauseQuizDto {
  @ApiProperty({
    description: 'UUID of the question the user paused on',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @IsUUID()
  @IsNotEmpty()
  pausedAtQuestionId: string;

  @ApiProperty({
    description: 'Remaining time in seconds when the quiz was paused',
    example: 120,
    minimum: 0,
  })
  @IsInt()
  @Min(0)
  @IsNotEmpty()
  remainingTimeSeconds: number;
}
