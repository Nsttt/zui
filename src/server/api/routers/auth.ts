import { z } from "zod";
import { createTRPCRouter, protectedProcedure } from "../trpc";
import { prisma } from "@/server/db";
import { TRPCError } from "@trpc/server";
import crypto from "crypto";
import { env } from "@/env.mjs";

export const UserSchema = z.object({
  username: z.string(),
  password: z.string().min(4),
});

export const authRouter = createTRPCRouter({
  createUser: protectedProcedure
    .input(UserSchema)
    .mutation(async ({ input }) => {
      const exists = await prisma.user.findFirst({
        where: { username: input.username },
      });

      if (exists) {
        throw new TRPCError({
          code: "CONFLICT",
          message: "User already exists",
        });
      }

      const hash = crypto.pbkdf2Sync(
        input.password,
        env.NEXTAUTH_SECRET,
        1000,
        64,
        "sha512"
      );

      await prisma.user.create({
        data: {
          username: input.username,
          password: hash.toString("hex"),
        },
      });
    }),
});
