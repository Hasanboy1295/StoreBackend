import { Router, Request, Response } from "express";
import passport, { Profile } from "passport";
import { Strategy as GoogleStrategy, VerifyCallback } from "passport-google-oauth20";
import MemberService from "./models/Member.service";
import AuthService from "./models/Auth.service";

const router = Router();
const memberService = new MemberService();
const authService = new AuthService();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: "/auth/google/callback",
    },
    async (
      accessToken: string,
      refreshToken: string,
      profile: Profile,
      done: VerifyCallback
    ) => {
      try {
        let user = await memberService.findOrCreateGoogleUser(profile);
        return done(null, user);
      } catch (err) {
        return done(err as Error, undefined);
      }
    }
  )
);

passport.serializeUser((user: any, done: (err: any, id?: any) => void) => done(null, user));
passport.deserializeUser((obj: any, done: (err: any, id?: any) => void) => done(null, obj));

router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  async (req: Request, res: Response) => {
    const user = req.user as any;
    const token = await authService.createToken(user);
    res.cookie("accessToken", token, {
      maxAge: 3 * 3600 * 1000,
      httpOnly: false,
      domain: "localhost",
      sameSite: "lax",
    });
    res.redirect("http://localhost:3000");
  }
);

export default router;