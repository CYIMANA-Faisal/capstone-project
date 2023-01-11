import { Body, Controller, Get, HttpCode, HttpStatus, Patch, Query } from '@nestjs/common';
import { ApiBadRequestResponse, ApiConflictResponse, ApiCreatedResponse, ApiExtraModels } from '@nestjs/swagger';
import { GenericResponse } from 'src/shared/interface/generic-response.interface';
import { getGenericResponseSchema } from 'src/shared/util/swagger.util';
import { FindUserDto } from './dto/find-user.dto';
import { User } from './entities/user.entity';
import { UsersService } from './users.service';
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}
  @ApiCreatedResponse({
    description: 'All users',
    ...getGenericResponseSchema(User),
  })
  @ApiExtraModels(User)
  @ApiConflictResponse({ description: 'All users' })
  @ApiBadRequestResponse({ description: 'Bad request' })
  @HttpCode(HttpStatus.OK)
  @Get('/allUsers')
  async findAllUsers(): Promise<GenericResponse<any>> {
    const result = await this.usersService.findAllUsers();
    return {
      message:'All users',
      results:result,
    };
  }

  @ApiCreatedResponse({
    description: 'user',
    ...getGenericResponseSchema(User),
  })
  @ApiExtraModels(User)
  @ApiConflictResponse({ description: 'A User' })
  @ApiBadRequestResponse({ description: 'Bad request' })
  @HttpCode(HttpStatus.OK)
  @Get('/AUser')
  async findUser(@Query()findUserDto:FindUserDto): Promise<GenericResponse<any>> {
    const result = await this.usersService.findUserByEmailOrPhoneNumber(findUserDto);
    return {
      message:'User found',
      results:result,
    };
  }

  @ApiCreatedResponse({
    description: 'Account activated successfully',
    ...getGenericResponseSchema(User),
  })
  @ApiExtraModels(User)
  @ApiConflictResponse({ description: 'Account activated successfully' })
  @ApiBadRequestResponse({ description: 'Bad request' })
  @HttpCode(HttpStatus.OK)
  @Patch('/activateUser')
  async changePassword( @Body() findUserDto: FindUserDto): Promise<GenericResponse<any>> {
    const result = await this.usersService.activateUser(findUserDto);
       return {
      message:'Account activated successfully' ,
      results: {user: result },
    };
  }

  @ApiCreatedResponse({
    description: 'Account Deactivated successfully',
    ...getGenericResponseSchema(User),
  })
  @ApiExtraModels(User)
  @ApiConflictResponse({ description: 'Account Deactivated successfully' })
  @ApiBadRequestResponse({ description: 'Bad request' })
  @HttpCode(HttpStatus.OK)
  @Patch('/deActivateUser')
  async DeActivateUser( @Body() findUserDto: FindUserDto): Promise<GenericResponse<any>> {
    const result = await this.usersService.DeActivateUser(findUserDto);
       return {
      message:'Account Deactivated successfully' ,
      results: {user: result },
    };
  }
}
