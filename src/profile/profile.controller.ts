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
import { ProfileService } from './profile.service';
import { CreateProfileDto } from './dto/create-profile.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import {
  ApiExtraModels,
  ApiConflictResponse,
  ApiBadRequestResponse,
  ApiTags,
  ApiCookieAuth,
} from '@nestjs/swagger';
import { Profile } from './entities/profile.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { User } from '../users/entities/user.entity';
import { omit } from 'lodash';

@ApiTags('profile')
@Controller('profile')
export class ProfileController {
  constructor(private readonly profileService: ProfileService) {}

  @ApiExtraModels(Profile)
  @ApiConflictResponse({ description: 'Profile created successfully' })
  @ApiBadRequestResponse({ description: 'Bad request' })
  @HttpCode(HttpStatus.OK)
  @ApiCookieAuth()
  @UseGuards(JwtAuthGuard)
  @Post('')
  async create(
    @GetUser() user: User,
    @Body() createProfileDto: CreateProfileDto,
  ) {
    const result = await this.profileService.create(user, createProfileDto);
    return {
      message: 'Profile created successfully',
      results: result,
    };
  }

  @Get('')
  async findAll() {
    const result = await this.profileService.findAll();
    return {
      message: 'User Profile Retrieved succssfully',
      results: { ...result },
    };
  }

  @Get('/:id')
  async findOne(@Param('id') id: string) {
    const result = await this.profileService.findOne(+id);
    return {
      message: 'User Profile Retrieved successfully',
      results: { ...result },
    };
  }

  @Patch('/:id')
  async update(
    @Param('id') id: string,
    @Body() updateProfileDto: UpdateProfileDto,
  ) {
    const result = await this.profileService.update(+id, updateProfileDto);
    return {
      message: 'User Profile Updated successfully',
      results: { ...result },
    };
  }

  @Delete('/:id')
  async remove(@Param('id') id: string) {
    await this.profileService.remove(+id);
    return {
      message: 'User Profile deleted successfully',
    };
  }
}
