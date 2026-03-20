import { PickType } from '@nestjs/swagger';
import { CreateAuthDto } from './signup.dto';

export class ForgetPasswordDto extends PickType(CreateAuthDto, [
  'email',
] as const) {}
