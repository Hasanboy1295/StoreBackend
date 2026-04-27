import { NextFunction, Request, Response } from "express";
import { OAuth2Client } from "google-auth-library";
import { T } from "../libs/types/common";
import MemberService from "../models/Member.service";
import {
  ExtendedRequest,
  LoginInput,
  Member,
  MemberInput,
  MemberUpdateInput,
} from "../libs/types/member";
import Errors, { HttpCode, Message } from "../libs/Errors";
import AuthService from "../models/Auth.service";
import { AUTH_TIMER } from "../libs/config";

const memberService = new MemberService();
const authService = new AuthService();
const memberController: T = {};

const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_CALLBACK_URL
);

memberController.signup = async (req: Request, res: Response) => {
  try {
    console.log("signup");
    const input: MemberInput = req.body;
    const result: Member = await memberService.signup(input);
    const token = await authService.createToken(result);
    res.cookie("accessToken", token, { maxAge: AUTH_TIMER * 3600 * 1000, httpOnly: false });
    res.status(HttpCode.CREATED).json({ member: result, accessToken: token });
  } catch (err) {
    console.log("Error, signup", err);
    if (err instanceof Errors) res.status(err.code).json(err);
    else res.status(Errors.standard.code).json(Errors.standard);
  }
};

memberController.login = async (req: Request, res: Response) => {
  try {
    console.log("login");
    const input: LoginInput = req.body;
    const result = await memberService.login(input);
    const token = await authService.createToken(result);
    res.cookie("accessToken", token, { maxAge: AUTH_TIMER * 3600 * 1000, httpOnly: false });
    res.status(HttpCode.OK).json({ member: result, accessToken: token });
  } catch (err) {
    console.log("Error, login", err);
    if (err instanceof Errors) res.status(err.code).json(err);
    else res.status(Errors.standard.code).json(Errors.standard);
  }
};

memberController.logout = (req: ExtendedRequest, res: Response) => {
  try {
    console.log("logout");
    res.cookie("accessToken", null, { maxAge: 0, httpOnly: true });
    res.status(HttpCode.OK).json({ logout: true });
  } catch (err) {
    console.log("Error, logout", err);
    if (err instanceof Errors) res.status(err.code).json(err);
    else res.status(Errors.standard.code).json(Errors.standard);
  }
};

memberController.updateMember = async (req: ExtendedRequest, res: Response) => {
  try {
    console.log("updateMember");
    const input: MemberUpdateInput = req.body;
    if (req.file) input.memberImage = req.file.path.replace(/\\/, "/");
    const result = await memberService.updateMember(req.member, input);
    res.status(HttpCode.OK).json(result);
  } catch (err) {
    console.log("Error, updateMember", err);
    if (err instanceof Errors) res.status(err.code).json(err);
    else res.status(Errors.standard.code).json(Errors.standard);
  }
};

memberController.getMemberDetail = async (req: ExtendedRequest, res: Response) => {
  try {
    console.log("getMemberDetail");
    const result = await memberService.getMemberDetail(req.member);
    res.status(HttpCode.OK).json(result);
  } catch (err) {
    console.log("Error getMemberDetail:", err);
    if (err instanceof Errors) res.status(err.code).json(err);
    else res.status(Errors.standard.code).json(Errors.standard);
  }
};

memberController.getTopUsers = async (req: Request, res: Response) => {
  try {
    console.log("getTopUsers");
    const result = await memberService.getTopUsers();
    res.status(HttpCode.OK).json(result);
  } catch (err) {
    console.log("Error getTopUsers:", err);
    if (err instanceof Errors) res.status(err.code).json(err);
    else res.status(Errors.standard.code).json(Errors.standard);
  }
};

memberController.getRestaurant = async (req: Request, res: Response) => {
  try {
    console.log("getRestaurant");
    const result = await memberService.getRestaurant();
    res.status(HttpCode.OK).json(result);
  } catch (err) {
    console.log("Error getRestaurant:", err);
    if (err instanceof Errors) res.status(err.code).json(err);
    else res.status(Errors.standard.code).json(Errors.standard);
  }
};

memberController.verifyAuth = async (req: ExtendedRequest, res: Response, next: NextFunction) => {
  try {
    const token = req.cookies["accessToken"];
    if (token) req.member = await authService.checkAuth(token);
    if (!req.member) throw new Errors(HttpCode.UNAUTHORIZED, Message.NOT_AUTHENTICATED);
    next();
  } catch (err) {
    console.log("Error, verifyAuth", err);
    if (err instanceof Errors) res.status(err.code).json(err);
    else res.status(Errors.standard.code).json(Errors.standard);
  }
};

memberController.retriveAuth = async (req: ExtendedRequest, res: Response, next: NextFunction) => {
  try {
    const token = req.cookies["accessToken"];
    if (token) req.member = await authService.checkAuth(token);
    next();
  } catch (err) {
    console.log("Error, retriveAuth", err);
    next();
  }
};

memberController.googleAuth = (req: Request, res: Response) => {
  try {
    console.log("googleAuth");
    const authUrl = googleClient.generateAuthUrl({
      access_type: "offline",
      scope: ["profile", "email"],
    });
    res.redirect(authUrl);
  } catch (err) {
    console.log("Error, googleAuth", err);
    if (err instanceof Errors) res.status(err.code).json(err);
    else res.status(Errors.standard.code).json(Errors.standard);
  }
};

memberController.googleCallback = async (req: Request, res: Response) => {
  try {
    console.log("googleCallback");
    const code = req.query.code as string;

    const { tokens } = await googleClient.getToken(code);
    googleClient.setCredentials(tokens);

    // await qo'shildi — asosiy xatolik shu edi
    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token as string,
      audience: process.env.GOOGLE_CLIENT_ID as string,
    });

    const payload = ticket.getPayload();
    if (!payload) throw new Errors(HttpCode.UNAUTHORIZED, Message.NOT_AUTHENTICATED);

    const googleData = {
      googleId: payload.sub as string,
      memberNick: (payload.name ?? payload.email ?? "user") as string,
      memberEmail: payload.email as string,
      memberImage: (payload.picture ?? "") as string,
    };

    const result = await memberService.findOrCreateGoogleUser(googleData);
    const token = await authService.createToken(result);

    res.cookie("accessToken", token, {
      maxAge: AUTH_TIMER * 3600 * 1000,
      httpOnly: false,
    });

    res.redirect("http://localhost:3000");
  } catch (err) {
    console.log("Error, googleCallback", err);
    if (err instanceof Errors) res.status(err.code).json(err);
    else res.status(Errors.standard.code).json(Errors.standard);
  }
};

export default memberController;