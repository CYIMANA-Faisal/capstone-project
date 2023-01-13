import {
  Injectable,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { omit } from 'lodash';
import { Repository } from 'typeorm';
import { Department } from '../department/entities/department.entity';
import { User } from '../users/entities/user.entity';
import { CreateProfileDto } from './dto/create-profile.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { Profile } from './entities/profile.entity';

@Injectable()
export class ProfileService {
  constructor(
    @InjectRepository(Profile)
    private readonly profileRepository: Repository<Profile>,
    @InjectRepository(Department)
    private readonly departmentRepository: Repository<Department>,
  ) {}

  async create(user: User, createProfileDto: CreateProfileDto) {
    const department = await this.departmentRepository.findOne({
      where: { id: createProfileDto.department_id },
    });
    if (!department) {
      throw new NotFoundException('Department not found');
    }
    const userProfile = this.profileRepository.create({
      ...omit(createProfileDto, ['department_id']),
      department: department,
      user: user,
    });
    const result = await this.profileRepository.save(userProfile);
    return omit(result, ['user']);
  }

  async findAll() {
    const result = await this.profileRepository.find();
    return {
      result,
    };
  }

  findOne(id: number) {
    //return `This action returns a #${id} profile`;
    return this.profileRepository.findOne(id);
  }

  async update(id: number, updateProfileDto: UpdateProfileDto) {
    //return `This action updates a #${id} profile`;
    const userProfileById = await this.findOne(id);
    if (!userProfileById) {
      throw new ConflictException('Profile you want to update does not exit');
    }
    return this.profileRepository.save({
      ...userProfileById,
      ...updateProfileDto,
    });
  }

  async remove(id: number) {
    //return `This action removes a #${id} profile`;
    const profile = await this.profileRepository.findOne({ id: id });
    if (!profile) {
      throw new ConflictException('Profile does not exit');
    }
    return this.profileRepository.delete(profile.id);
  }
}
