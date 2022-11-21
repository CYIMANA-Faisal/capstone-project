import { AppController } from './app.controller';
import { AppService } from './app.service';
import { runtimeConfig } from './shared/config/app.config';
import { TypeOrmFactoryConfigService } from './shared/config/typeorm-factory-config.service';
import { DatabaseExceptionFilter } from './shared/filters/database-exception.filter';
import { HttpExceptionFilter } from './shared/filters/http-exception.filter';
import { AuditInterceptor } from './shared/interceptors/audit.interceptor';
import { ClassTransformInterceptor } from './shared/interceptors/class-transform.interceptor';
import { ResponseTransformInterceptor } from './shared/interceptors/response-transform.interceptor';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { Module, OnApplicationBootstrap } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [runtimeConfig],
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useClass: TypeOrmFactoryConfigService,
    }),
    AuthModule,
    UsersModule,
  ],
  controllers: [AppController],
  providers: [
    { provide: APP_FILTER, useClass: HttpExceptionFilter },
    { provide: APP_FILTER, useClass: DatabaseExceptionFilter },
    { provide: APP_INTERCEPTOR, useClass: AuditInterceptor },
    { provide: APP_INTERCEPTOR, useClass: ResponseTransformInterceptor },
    { provide: APP_INTERCEPTOR, useClass: ClassTransformInterceptor },
    AppService,
    // UserSeedService,
  ],
})
export class AppModule implements OnApplicationBootstrap {
  //constructor() {} // private readonly programPreferenceSeedService: ProgramPreferenceSeedService, // private readonly interestPreferenceSeedService: InterestPreferenceSeedService, // private readonly assessmentRequestSeedService: AssessmentRequestSeedService, // private readonly assessmentSeedService: AssessmentSeedService, // private readonly gradesSeedService: GradesSeedService, // private readonly employmentStatusSeedService: EmploymentStatusPreferenceSeedService, // private readonly opportunityTypePreferenceSeedService: OpportunityTypePreferenceSeedService, // private readonly gradingSeedService: GradingPreferenceSeedService, // private readonly languageSeedService: LanguagePreferenceSeedService, // private readonly specializationSeedService: SpecializationPreferenceSeedService, // private readonly educationSeedService: EducationPreferenceSeedService, // private readonly userSeedService: UserSeedService,
  async onApplicationBootstrap() {
    // await this.userSeedService.seed();
    // await this.educationSeedService.seed();
    // await this.languageSeedService.seed();
    // await this.specializationSeedService.seed();
    // await this.gradingSeedService.seed();
    // await this.opportunityTypePreferenceSeedService.seed();
    // await this.employmentStatusSeedService.seed();
    // await this.assessmentSeedService.seed();
    // await this.assessmentRequestSeedService.seed();
    // await this.interestPreferenceSeedService.seed();
    // await this.programPreferenceSeedService.seed();
  }
}
