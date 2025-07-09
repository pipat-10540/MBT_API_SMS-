import { Schema, z } from "zod";
export const groupsSchema = z.object({
  id: z.number().optional(),
  group_name: z.string().optional(),
  contact_id: z.number().optional(),
  create_date: z.string().optional(),
  last_update: z.string().optional(),
});

export const DeletegroupsSchema = z.object({
  id: z.array(z.number()),
});
export type contact = z.infer<typeof groupsSchema>;
