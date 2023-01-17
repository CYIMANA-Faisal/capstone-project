import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserRole } from 'src/shared/enums/user-roles.enum';
import { Repository } from 'typeorm';
import { BcryptService } from '../shared/util/bcrypt.service';
import { UpdateUserRoleDto } from './dto/updateUserRole.dto';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private readonly bcryptService: BcryptService,
  ) {}
  async updateUserRole(updateUserRoleDto:UpdateUserRoleDto){
const user=await this.userRepository.findOne({id:updateUserRoleDto.id});
if(!user){
  throw new NotFoundException('This user does not exist');
}
const updatedUser=await this.userRepository.update({id:updateUserRoleDto.id},
  {role:updateUserRoleDto.role});
  return {message:'User role updated successfully',
    updated_User:updatedUser};
  }
  
}
