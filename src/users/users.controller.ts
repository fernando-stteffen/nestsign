import {
    Body,
    Controller,
    Get,
    HttpCode,
    HttpStatus,
    Post,
    UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { SignInDto } from './dtos/signin.dto';
import { SignUpDto } from './dtos/signup.dto';
import { User } from './models/users.model';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UsersService) {}

    @Post('signup')
    @HttpCode(HttpStatus.CREATED)
    public async signup(@Body() signUpDto: SignUpDto): Promise<User> {
        return this.usersService.singUp(signUpDto);
    }

    @Post('signin')
    @HttpCode(HttpStatus.OK)
    public async signin(
        @Body() signInDto: SignInDto,
    ): Promise<{ name: string; jwtToken: string; email: string }> {
        return this.usersService.signIn(signInDto);
    }

    @Get()
    @HttpCode(HttpStatus.OK)
    @UseGuards(AuthGuard('jwt'))
    public async findAll(): Promise<User[]> {
        return this.usersService.findAll();
    }
}
