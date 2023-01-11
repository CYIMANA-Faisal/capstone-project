import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateDepartmentDto } from './dto/create-department.dto';
import { UpdateDepartmentDto } from './dto/update-department.dto';
import { Department } from './entities/department.entity';

@Injectable()
export class DepartmentService {
  constructor(
    @InjectRepository(Department)
    private readonly departmentRepository: Repository<Department>,
  ) {}

  create(createDepartmentDto: CreateDepartmentDto);
  async create(createDepartmentDto: CreateDepartmentDto) {
    const userProfile = this.departmentRepository.create(createDepartmentDto);
    const result = await this.departmentRepository.save(userProfile);
    return {
      result,
    };
  }

  async findAll() {
    const result = await this.departmentRepository.find();
    return {
      result,
    };
  }

  findOne(id: number) {
    //return `This action returns a #${id} profile`;
    return this.departmentRepository.findOne(id);
  }

  async update(id: number, updateDepartmentDto: UpdateDepartmentDto) {
    //return `This action updates a #${id} profile`;
    const userDepartmentById = await this.findOne(id);
    return this.departmentRepository.save({
      ...userDepartmentById,
      ...updateDepartmentDto,
    });
  }

  async remove(id: number) {
    //return `This action removes a #${id} profile`;
    const deleteDepartment = await this.findOne(id);
    return this.departmentRepository.remove(deleteDepartment);
  }
}
