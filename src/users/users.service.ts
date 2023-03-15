import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
import { AuthService } from 'src/auth/auth.service';
import { SignInDto } from './dtos/signin.dto';
import { SignUpDto } from './dtos/signup.dto';
import { User } from './models/users.model';

@Injectable()
export class UsersService {
    constructor(
        @InjectModel('User') private readonly usersModel: Model<User>,
        private readonly authService: AuthService,
    ) {}

    public async singUp(signUpDto: SignUpDto): Promise<User> {
        const user = new this.usersModel(signUpDto);
        return user.save();
    }

    public async signIn(
        singinDto: SignInDto,
    ): Promise<{ name: string; jwtToken: string; email: string }> {
        const user = await this.findByEmail(singinDto.email);
        const match = await this.isValidPassword(singinDto.password, user);

        if (!match) throw new NotFoundException('Invalid credentials');

        const jwtToken = await this.authService.createAccessToken(user._id);

        return { name: user.name, jwtToken, email: user.email };
    }

    public async findAll(): Promise<User[]> {
        return this.usersModel.find();
    }

    private async findByEmail(email: string): Promise<User> {
        const user = await this.usersModel.findOne({ email });
        if (!user) throw new NotFoundException('Email not founded');

        return user;
    }

    private async isValidPassword(
        password: string,
        user: User,
    ): Promise<boolean> {
        const match = await bcrypt.compare(password, user.password);
        if (!match) throw new NotFoundException('Password not founded');

        return match;
    }
}
