import { Body, Controller, HttpCode, HttpStatus, Patch, UseFilters, UseGuards } from '@nestjs/common';
import { ApiBadRequestResponse, ApiConflictResponse, ApiCookieAuth, ApiCreatedResponse, ApiExtraModels, ApiTags } from '@nestjs/swagger';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { UserRole } from 'src/shared/enums/user-roles.enum';
import { HttpExceptionFilter } from 'src/shared/filters/http-exception.filter';
import { GenericResponse } from 'src/shared/interface/generic-response.interface';
import { getGenericResponseSchema } from 'src/shared/util/swagger.util';
import { UpdateUserRoleDto } from './dto/updateUserRole.dto';
import { User } from './entities/user.entity';
import { UsersService } from './users.service';

@ApiTags('Users')
@Controller('users')
@UseFilters(HttpExceptionFilter)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}
  
  @ApiCreatedResponse({
    description: 'User role updated',
    ...getGenericResponseSchema(User),
  })
  @ApiExtraModels(User)
  @ApiBadRequestResponse({ description: 'Bad request' })
  @HttpCode(HttpStatus.OK)
  @ApiCookieAuth()
  @Roles(UserRole.ADMIN)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Patch('/updateUserRole')
  async updateUserRole(@Body() updateUserRoleDto:UpdateUserRoleDto):Promise<GenericResponse<any>> {
  const result=await this.usersService.updateUserRole(updateUserRoleDto);
return {message:'User role update successfully',
        results:result}
  }
}
