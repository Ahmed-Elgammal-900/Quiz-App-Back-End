import { IsUUID, IsNotEmpty } from 'class-validator';

export class InsertProgressDto {
  @IsUUID()
  @IsNotEmpty()
  questionId: string;

  @IsUUID()
  @IsNotEmpty()
  selectedAnswerId: string;
}
