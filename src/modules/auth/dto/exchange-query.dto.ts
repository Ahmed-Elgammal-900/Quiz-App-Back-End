import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class ExchangeQueryDto {
  @ApiProperty({
    description: 'The authorization code to get user tokens',
    example: 'abc123xyz',
    type: String,
  })
  @IsString()
  @IsNotEmpty()
  code!: string;
}
