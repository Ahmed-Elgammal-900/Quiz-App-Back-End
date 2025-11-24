import { OmitType } from "@nestjs/mapped-types";
import { CreateAuthDto } from "./create-auth.dto";

export class LoginDto extends OmitType(CreateAuthDto, ['name'] as const){}