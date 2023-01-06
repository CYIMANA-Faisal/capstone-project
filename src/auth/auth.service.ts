import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
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
import { addDays, addMinutes, formatISO, isBefore, isEqual } from 'date-fns';
import { VerifyBy } from 'src/shared/enums/verify.enum';
import {
  ACCOUNT_ALREADY_VERIFIED,
  ACCOUNT_IN_DORMANT_MODE,
  EMAIL_OR_PHONE_NUMBER_IS_REQUIRED,
  INVALID_CREDENTIAL,
  INVALID_VERIFICATION_CODE,
  NO_ACCESS_TO_THE_PORTAL,
  UNVERIFIED_ACCOUNT,
  VERIFICATION_CODE_EXPIRED,
  VERIFICATION_EMAIL_SUBJECT,
  YOU_CAN_LOGIN_WITH_EITHER_EMAIL_OR_PHONE_NUMBER,
} from 'src/shared/constants/auth.constants';

import { TokenPayload } from './interfaces/jwt.payload.interface';
import { USER_NOT_FOUND } from 'src/shared/constants/user.constants';
import { EMAIL_REGEX } from 'src/shared/constants/regex.constant';
import { Code } from 'src/users/entities/code.entity';
import { UserRole } from '../shared/enums/user-roles.enum';
import { ChangePasswordDto } from './dto/change-password.dto';
import { LoginDto } from './dto/login.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Code)
    private readonly verificationCodeRepository: Repository<Code>,
    private readonly jwtService: JwtService,
    private readonly sendGridService: SendGrindService,
    //private readonly connection: Connection,
    // private readonly smsService: SmsService,
    private readonly configService: ConfigService,
    private readonly bcryptService: BcryptService,
  ) {}

  async registerUser(createUserDto: CreateUserDto): Promise<any> {
    const user = { ...createUserDto };
    user.password = await this.bcryptService.hash(user.password);
    if (await this.checkUserExisting(user.email)) {
      throw new ConflictException('User with this email already exist.');
    } else {
      const registeredUser = await this.userRepository.save({
        email: user.email,
        password: user.password,
        phone_number: user.phone_number,
        first_name: user.first_name,
        last_name: user.last_name,
        manager: null,
        role: UserRole.STANDARD,
      });
      const verificationCode = codeGenerator();
      await this.verificationCodeRepository.save({
        code: verificationCode,
        user: registeredUser,
        expiryDate: formatISO(addMinutes(new Date(), 10), {
          representation: 'complete',
        }),
      });
      const verificationMail = {
        to: user.email,
        subject: VERIFICATION_EMAIL_SUBJECT,
        from: this.configService.get<string>('SENT_EMAIL_FROM'),
        text: `Hello verify the account`,
        html: `<h1>Hello @ ${registeredUser.first_name} please use the code below to verify your account ${verificationCode} </h1>`,
      };
      await this.sendGridService.send(verificationMail);
      return omit(registeredUser, ['password', 'currentHashedRefreshToken']);
    }
    return user;
  }

  async checkUserExisting(email: string): Promise<boolean> {
    const user = await this.userRepository.findOne({ email: email });
    //console.log(user)
    if (user) {
      return true;
    } else {
      return false;
    }
  }
  async requestVerification(emailorPhone: string): Promise<void> {
    const user = await this.findUserByEmailOrPhoneNumber(emailorPhone);
    if (!user) {
      throw new UnauthorizedException(USER_NOT_FOUND);
    }
    if (user.isVerified) {
      throw new BadRequestException(ACCOUNT_ALREADY_VERIFIED);
    }
    const verificationCodeEntry = {
      code: codeGenerator(),
      expiryDate: formatISO(addMinutes(new Date(), 10), {
        representation: 'complete',
      }),
      user: user,
    };
    await this.verificationCodeRepository.delete({ user: user });
    const verificationCode = await this.verificationCodeRepository.save(
      verificationCodeEntry,
    );
    if (this.checkDataIsEmail(emailorPhone)) {
      const body: string =
        'Hello ' +
        user.first_name +
        ', Please verify your account by entering this code: ' +
        verificationCode.code;
      const verificationMail = {
        to: user.email,
        subject: VERIFICATION_EMAIL_SUBJECT,
        from: process.env.SENT_EMAIL_FROM,
        text: body,
        html: '<h1>' + body + '</h2>',
      };
      await this.sendGridService.send(verificationMail);
    }
  }
  findUserByEmailOrPhoneNumber(emailorPhone): Promise<User> {
    if (
      !this.checkDataIsEmail(emailorPhone) &&
      !this.checkDataIsPhone(emailorPhone)
    ) {
      throw new BadRequestException(EMAIL_OR_PHONE_NUMBER_IS_REQUIRED);
    }
    let user = null;
    if (this.checkDataIsEmail(emailorPhone)) {
      user = this.userRepository.findOne({
        email: emailorPhone,
      });
    }
    if (this.checkDataIsPhone(emailorPhone)) {
      user = this.userRepository.findOne({ phone_number: emailorPhone });
    }
    return user;
  }
  async findUserByEmail(email: string): Promise<User> {
    const user = await this.userRepository.findOne({
      email: email,
    });
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
  async verification(code: string): Promise<any> {
    const result = await this.verificationCodeRepository.findOne({
      where: { code: code },
      relations: ['user'],
    });
    if (!result) {
      throw new UnauthorizedException(INVALID_VERIFICATION_CODE);
    }
    if (!(await this.checkCodeExpiry(result))) {
      throw new UnauthorizedException(VERIFICATION_CODE_EXPIRED);
    }
    await this.userRepository.update(
      { id: result.user.id },
      { isVerified: true },
    );
    await this.verificationCodeRepository.delete({
      id: result.id,
    });
    /* const accessToken = this.getJwtAccessToken(
    user.id, user.email,
    user.first_name,user.last_name,user.manager_id,
  );
  const refreshToken = this.getJwtRefreshToken(
    user.id, user.email,
    user.first_name,user.last_name,user.manager_id,
  );*/
    return {
      // accessToken,
      // refreshToken,
      user: omit(result.user, ['password', 'currentHashedRefreshToken']),
    };
  }
  public getJwtAccessToken(user: User): string {
    const payload = { id: user.id, email: user.email, role: user.role };
    const token = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: this.configService.get<string>(
        'JWT_ACCESS_TOKEN_EXPIRATION_TIME',
      ),
    });
    return token;
  }

  public getJwtRefreshToken(user: User): string {
    const payload = { id: user.id, email: user.email, role: user.role };
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: this.configService.get<string>(
        'JWT_REFRESH_TOKEN_EXPIRATION_TIME',
      ),
    });
    return refreshToken;
  }
  async checkCodeExpiry(data: Code): Promise<boolean> {
    if (isBefore(new Date(), new Date(data.expiryDate))) {
      return true;
    }
    return false;
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
  async login(loginDto: LoginDto) {
    const user = await this.findUserByEmail(loginDto.email);
    const isPasswordValid = await this.bcryptService.compare(
      loginDto.password,
      user?.password ? user.password : 'no password',
    );
    if (!user || !isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    if (!user.isVerified) {
      throw new UnauthorizedException(UNVERIFIED_ACCOUNT);
    }
    if (!user.active) {
      throw new UnauthorizedException(ACCOUNT_IN_DORMANT_MODE);
    }
    const results = {
      accessToken: await this.getJwtAccessToken(user),
      refreshToken: await this.getJwtRefreshToken(user),
    };
    const token = this.jwtService.verify(results.accessToken, {
      secret: this.configService.get<string>('JWT_ACCESS_TOKEN_SECRET'),
    });
    console.log(token.id, token.role);
    await this.setCurrentHashedRefreshToken(results.refreshToken, user.id);
    return results;
  }

  async setCurrentHashedRefreshToken(refreshToken: string, id: number) {
    const hashedRefreshToken = await this.bcryptService.hash(refreshToken);
    await this.userRepository.update(
      { id: id },
      { currentHashedRefreshToken: hashedRefreshToken },
    );
  }
  async changePassword(
    userId: number,
    psdDto: ChangePasswordDto,
  ): Promise<any> {
    const user = await this.userRepository.findOne({ id: userId });
    if (
      !(await this.bcryptService.compare(psdDto.currentPassword, user.password))
    ) {
      throw new ConflictException(
        "The current and existing passwords don't match",
      );
    }
    if (psdDto.currentPassword === psdDto.newPassword) {
      throw new ConflictException("The current and new passwords can't match");
    }
    const updateduser = await this.userRepository.update(
      { id: user.id },
      { password: await this.bcryptService.hash(psdDto.newPassword) },
    );
    return {
      user: omit(updateduser, ['password', 'currentHashedRefreshToken']),
    };
  }
  async forgotPassword(email: string): Promise<User> {
    const user = await this.findUserByEmail(email);
    if (!user) {
      throw new ConflictException('User not found');
    }
    if (!user.isVerified) {
      throw new ConflictException(UNVERIFIED_ACCOUNT);
    }
    const verificationCode = codeGenerator();
    await this.verificationCodeRepository.save({
      code: verificationCode,
      user: user,
      expiryDate: formatISO(addMinutes(new Date(), 10), {
        representation: 'complete',
      }),
    });
    const verificationMail = {
      to: user.email,
      subject: VERIFICATION_EMAIL_SUBJECT,
      from: this.configService.get<string>('SENT_EMAIL_FROM'),
      text: `Hello verify the account`,
      html: `<h1>Hello @ ${user.first_name} please use the code below to verify your account ${verificationCode} </h1>`,
    };
    await this.sendGridService.send(verificationMail);
    return user;
  }
  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const user = await this.findUserByEmail(resetPasswordDto.email);
    resetPasswordDto.password = await this.bcryptService.hash(
      resetPasswordDto.password,
    );
    const isPasswordValid = await this.bcryptService.compare(
      resetPasswordDto.confirmPassword,
      resetPasswordDto.password,
    );
    if (!user) {
      throw new UnauthorizedException('Invalid email');
    }
    if (!isPasswordValid) {
      throw new ConflictException("passwords don't match");
    }
    if (!user.isVerified) {
      throw new UnauthorizedException(UNVERIFIED_ACCOUNT);
    }
    const updatedPass = await this.userRepository.update(
      { email: user.email },
      { password: resetPasswordDto.password },
    );
    return {
      user: omit(updatedPass, ['password', 'currentHashedRefreshToken']),
    };
  }
  async requestPasswordCode(emailorPhone: string): Promise<void> {
    const user = await this.findUserByEmailOrPhoneNumber(emailorPhone);
    if (!user) {
      throw new UnauthorizedException(USER_NOT_FOUND);
    }
    if (!user.isVerified) {
      throw new BadRequestException(UNVERIFIED_ACCOUNT);
    }
    const verificationCodeEntry = {
      code: codeGenerator(),
      expiryDate: formatISO(addMinutes(new Date(), 10), {
        representation: 'complete',
      }),
      user: user,
    };
    await this.verificationCodeRepository.delete({ user: user });
    const verificationCode = await this.verificationCodeRepository.save(
      verificationCodeEntry,
    );
    if (this.checkDataIsEmail(emailorPhone)) {
      const body: string =
        'Hello ' +
        user.first_name +
        ', Please verify your account by entering this code: ' +
        verificationCode.code;
      const verificationMail = {
        to: user.email,
        subject: VERIFICATION_EMAIL_SUBJECT,
        from: process.env.SENT_EMAIL_FROM,
        text: body,
        html: '<h1>' + body + '</h2>',
      };
      await this.sendGridService.send(verificationMail);
    }
  }
}
