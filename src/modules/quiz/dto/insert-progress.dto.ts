import { IsUUID, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class InsertProgressDto {
  @ApiProperty({
    description: 'UUID of the question being answered',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @IsUUID()
  @IsNotEmpty()
  questionId!: string;

  @ApiProperty({
    description: 'UUID of the selected answer',
    example: 'b4cc290f-9ca0-4999-0023-bdf5f7654113',
  })
  @IsUUID()
  @IsNotEmpty()
  selectedAnswerId!: string;
}
