import { Injectable, HttpException, HttpStatus, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../users/entities/user.entity';
import { Repository } from 'typeorm';
import { CreateProfileDto } from './dto/create-profile.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { Profile } from './entities/profile.entity';

@Injectable()
export class ProfileService {
  constructor(
    @InjectRepository(Profile)
    private readonly profileRepository: Repository<Profile>,
  ) {}

  async create(createProfileDto: CreateProfileDto) {
    const userProfile = this.profileRepository.create(createProfileDto);
    const result = await this.profileRepository.save(userProfile);
    return {
      result,
    };
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
    if (!userProfileById){
      throw new ConflictException("Profile you want to update does not exit");
    }
     return this.profileRepository.save({
      ...userProfileById,
      ...updateProfileDto,
    });
  }

  async remove(id: number) {
    //return `This action removes a #${id} profile`;
    const profile = await this.profileRepository.findOne({id:id});
    if (!profile){
      throw new ConflictException("Profile does not exit");
    }
    return this.profileRepository.delete(profile.id);
  }
}
