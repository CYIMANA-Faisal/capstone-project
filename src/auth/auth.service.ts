import {
  ConflictException,
  Injectable,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { SendGrindService } from '../notifications/sendgrid.service';
import { Connection } from 'typeorm';
import { User } from '../users/entities/user.entity';
import { BcryptService } from '../shared/util/bcrypt.service';
import { ConfigService } from '@nestjs/config';
import { SmsService } from '../notifications/sms.service';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { omit } from 'lodash';
import { codeGenerator } from 'src/shared/util/code-generator';
import { addDays, formatISO } from 'date-fns';
import { VerifyBy } from 'src/shared/enums/verify.enum';
import { VERIFICATION_EMAIL_SUBJECT } from 'src/shared/constants/auth.constants';
import { VerificationCode } from './entities/verification-code.entities';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(VerificationCode)
    private readonly verificationCodeRepository: Repository<VerificationCode>,
    private readonly jwtService: JwtService,
    private readonly sendGridService: SendGrindService,
    private readonly connection: Connection,
    private readonly smsService: SmsService,
    private readonly configService: ConfigService,
    private readonly bcryptService: BcryptService,
  ) {}

  async registrUser(user: CreateUserDto): Promise<any>{
    user.password = await this.bcryptService.hash(user.password);
    if(! await this.checkUserExisting(user.email)){
      const createdUser = await this.userRepository.save(user)
      return omit(createdUser, ['password', 'gender'])
    }else{
      throw new ConflictException('User already exist.')
    }
    const verificationCode: string = codeGenerator();
    const verificationCodeEntry = {
      code: verificationCode,
      expiryDate: formatISO(new Date(addDays(new Date(), 1)), {
        representation: 'complete',
      }),
      user: user,
    };
   /* const userVerificationCode = await this.verificationCodeRepository.save(
      VerificationCode,
      verificationCodeEntry,
    );*/
    if (user.verifyBy === VerifyBy.EMAIL) {
      const verificationMail = {
        to: user.email,
        subject: VERIFICATION_EMAIL_SUBJECT,
        from: this.configService.get<string>('SENT_EMAIL_FROM'),
        text: `Hello verify the account`,
        //html: emailVerificationTemplate(
       //   user.firstName,
       //   userVerificationCode.code,
       // ),
      };
      await this.sendGridService.send(verificationMail);
    }

   
 
  }

  async checkUserExisting(email: string): Promise<boolean>{
    const user = await this.userRepository.findOne({email: email});
    console.log(user)
    if (user) {
      return true
    } else {
      return false
    }
  }
  
  
  async checkIfRefreshTokenMatching(
    refreshToken: string,
    hashedRefreshedToken: string,
  ): Promise<boolean> {
    const isRefreshTokenMatching = await this.bcryptService.compare(
      refreshToken,
      hashedRefreshedToken,
    );
    return isRefreshTokenMatching;
  }
}
