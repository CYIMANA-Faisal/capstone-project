import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { omit } from 'lodash';
import {
  IPaginationOptions,
  paginate,
  Pagination,
} from 'nestjs-typeorm-paginate';
import { UNVERIFIED_ACCOUNT } from 'src/shared/constants/auth.constants';
import { EMAIL_REGEX } from 'src/shared/constants/regex.constant';
import { Repository } from 'typeorm';
import { UserRole } from '../shared/enums/user-roles.enum';
import { BcryptService } from '../shared/util/bcrypt.service';
import { FindUserDto } from './dto/find-user.dto';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private readonly bcryptService: BcryptService,
  ) {}
  async findUserByEmailOrPhoneNumber(findUserDto: FindUserDto): Promise<User> {
    if (
      !this.checkDataIsEmail(findUserDto.emailOrPhone) &&
      !this.checkDataIsPhone(findUserDto.emailOrPhone)
    ) {
      throw new BadRequestException('Please use either email or phonenumber');
    }
    let user = new User();
    if (this.checkDataIsEmail(findUserDto.emailOrPhone)) {
      user = await this.userRepository.findOne({
        email: findUserDto.emailOrPhone,
      });
      if(!user){
        throw new BadRequestException('User not found');
      }
    }
    if (this.checkDataIsPhone(findUserDto.emailOrPhone)) {
      user = await this.userRepository.findOne({
        phone_number: findUserDto.emailOrPhone,
      });
      if(!user){
        throw new BadRequestException('User not found');
      }
    }
    return user;
  }
  checkDataIsEmail(email: string): boolean {
    if (EMAIL_REGEX.test(email)) {
      return true;
    } else {
      return false;
    }
  }

  checkDataIsPhone(phone: string): boolean {
    phone = phone.split(' ').join('');
    if (phone.startsWith('+250') && phone.length === 13) {
      return true;
    } else {
      return false;
    }
  }
  
    async findAllUsers():Promise<any>{
      const users=await this.userRepository.find();
      return{users};
    }
    async activateUser(findUserDto:FindUserDto){
      const user=await this.findUserByEmailOrPhoneNumber(findUserDto);
      if(!user){
        throw new BadRequestException('User not found');
      }
      if(!user.isVerified){
        throw new BadRequestException(UNVERIFIED_ACCOUNT);
      }
      if(user.active){
        throw new BadRequestException('Your account is already active');
      }
      
      if(this.checkDataIsEmail(findUserDto.emailOrPhone)){
        const activate=await this.userRepository.update(
          {email:findUserDto.emailOrPhone},
          {active:true});
          return activate;
      }
      if(this.checkDataIsPhone(findUserDto.emailOrPhone)){
        const activate=await this.userRepository.update(
          {phone_number:findUserDto.emailOrPhone},
          {active:true});
      }
      
    }
    async DeActivateUser(findUserDto:FindUserDto){
      const user=await this.findUserByEmailOrPhoneNumber(findUserDto);
      if(!user){
        throw new BadRequestException('User not found');
      }
      if(!user.isVerified){
        throw new BadRequestException(UNVERIFIED_ACCOUNT);
      }
      if(!user.active){
        throw new BadRequestException('Your account is already not active');
      }
      if(this.checkDataIsEmail(findUserDto.emailOrPhone)){
        const deActivate=await this.userRepository.update(
          {email:findUserDto.emailOrPhone},
          {active:false});
      }
      if(this.checkDataIsPhone(findUserDto.emailOrPhone)){
        const deActivate=await this.userRepository.update(
          {phone_number:findUserDto.emailOrPhone},
          {active:false});
      }
    }
}
