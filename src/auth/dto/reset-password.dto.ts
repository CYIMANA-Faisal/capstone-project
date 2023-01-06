import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, Matches } from 'class-validator';

export class ResetPasswordDto {
  @ApiProperty()
  @IsEmail()
  @IsNotEmpty()
  @IsString()
  email: string;

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  @Matches(/^(?=.*[\d])(?=.*[a-z])(?=.*[A-Z]).{8,16}$/, {
    message: 'Password is weak',
  })
  password: string;

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  @Matches(/^(?=.*[\d])(?=.*[a-z])(?=.*[A-Z]).{8,16}$/, {
    message: 'Password is weak',
  })
  confirmPassword: string;
}
