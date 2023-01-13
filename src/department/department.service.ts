import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { omit } from 'lodash';
import { Repository } from 'typeorm';
import { User } from '../users/entities/user.entity';
import { CreateDepartmentDto } from './dto/create-department.dto';
import { UpdateDepartmentDto } from './dto/update-department.dto';
import { Department } from './entities/department.entity';

@Injectable()
export class DepartmentService {
  constructor(
    @InjectRepository(Department)
    private readonly departmentRepository: Repository<Department>,

    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  create(createDepartmentDto: CreateDepartmentDto);
  async create(createDepartmentDto: CreateDepartmentDto) {
    const hod = await this.userRepository.findOne({
      where: { id: createDepartmentDto.hod },
    });
    const department = this.departmentRepository.create({
      ...omit(createDepartmentDto, ['hod']),
      hod: hod ? hod : null,
    });
    const result = await this.departmentRepository.save(department);
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
    const department = await this.departmentRepository.findOne({
      where: { id: id },
    });
    if (!department) {
      throw new NotFoundException('Department not found');
    }
    let hod;
    if (updateDepartmentDto?.hod) {
      hod = await this.userRepository.findOne({
        where: { id: updateDepartmentDto.hod },
      });
    }
    return await this.departmentRepository.update(
      { id: department.id },
      {
        department_name: updateDepartmentDto.department_name,
        hod: hod ? hod : null,
      },
    );
  }

  async remove(id: number) {
    //return `This action removes a #${id} profile`;
    const deleteDepartment = await this.findOne(id);
    return this.departmentRepository.remove(deleteDepartment);
  }
}
