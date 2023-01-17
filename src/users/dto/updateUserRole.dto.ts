import { ApiProperty } from "@nestjs/swagger";
import { IsEnum, IsNotEmpty, IsNumber } from "class-validator";
import { UserRole } from "src/shared/enums/user-roles.enum";

export class UpdateUserRoleDto{

@ApiProperty()
@IsNotEmpty()
@IsNumber()
id:number;

@ApiProperty()
@IsNotEmpty()
@IsEnum(UserRole)
role:UserRole;

}