import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiCookieAuth,
  ApiCreatedResponse,
  ApiExtraModels,
  ApiTags,
} from '@nestjs/swagger';
import { Roles } from '../auth/decorators/roles.decorator';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { UserRole } from '../shared/enums/user-roles.enum';
import { getGenericResponseSchema } from '../shared/util/swagger.util';
import { DepartmentService } from './department.service';
import { CreateDepartmentDto } from './dto/create-department.dto';
import { UpdateDepartmentDto } from './dto/update-department.dto';
import { Department } from './entities/department.entity';

@ApiTags('department')
@Controller('department')
export class DepartmentController {
  constructor(private readonly departmentService: DepartmentService) {}

  @ApiCreatedResponse({
    description: 'Password changed successfully',
    ...getGenericResponseSchema(Department),
  })
  @ApiExtraModels(Department)
  @ApiCookieAuth()
  @ApiBadRequestResponse({ description: 'Bad request' })
  @HttpCode(HttpStatus.OK)
  @Roles(UserRole.ADMIN)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Post('')
  async create(@Body() createDepartmentDto: CreateDepartmentDto) {
    const result = await this.departmentService.create(createDepartmentDto);
    return {
      message: 'Department created successfully',
      results: { ...result },
    };
  }

  @Get()
  async findAll() {
    const result = await this.departmentService.findAll();
    return {
      message: 'Department Getall successfully',
      results: { ...result },
    };
  }

  @Get('/:id')
  async findOne(@Param('id') id: string) {
    const result = await this.departmentService.findOne(+id);
    return {
      message: 'Department Get byId successfully',
      results: { ...result },
    };
  }

  @ApiCookieAuth()
  @Roles(UserRole.ADMIN)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Patch('/:id')
  async update(
    @Param('id') id: string,
    @Body() updateDepartmentDto: UpdateDepartmentDto,
  ) {
    const result = await this.departmentService.update(
      +id,
      updateDepartmentDto,
    );
    return {
      message: 'Department Update successfully',
      results: { ...result },
    };
  }

  @ApiCookieAuth()
  @Roles(UserRole.ADMIN)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Delete('/:id')
  async remove(@Param('id') id: string) {
    const result = await this.departmentService.remove(+id);

    return {
      message: 'Department Deleted successfully',
      results: { ...result },
    };
  }
}
