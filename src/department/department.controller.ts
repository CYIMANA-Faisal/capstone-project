import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { DepartmentService } from './department.service';
import { CreateDepartmentDto } from './dto/create-department.dto';
import { UpdateDepartmentDto } from './dto/update-department.dto';

@Controller('department')
export class DepartmentController {
  constructor(private readonly departmentService: DepartmentService) {}

  @Post('/createdepartment')
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

  @Get(':id')
  async findOne(@Param('id') id: string) {
    const result = await this.departmentService.findOne(+id);
    return {
      message: 'Department Get byId successfully',
      results: { ...result },
    };
  }

  @Patch(':id')
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

  @Delete(':id')
  async remove(@Param('id') id: string) {
    const result = await this.departmentService.remove(+id);

    return {
      message: 'Department Deleted successfully',
      results: { ...result },
    };
  }
}
