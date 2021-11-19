const mongoose = require("mongoose"),
   Schema = mongoose.Schema,
   config = require("@config/vars"),
   moment = require('moment-timezone'),
   uuidv1 = require("uuid/v1")

const sessionSchema = new Schema(
   {
      entity: { type: Schema.Types.ObjectId, required: true },
      type: {type: String},
      firstName: { type: String },
      lastName: { type: String },
      role: { type: String },
      ipAddress: { type: String },
      token: { type: String, required: true },
      loginTime: { type: Date, default: new Date() },
      logoutTime: {
         type: Date
      },
      device: {},
      isActive: { type: Boolean, default: true },
      channel: { type: String, enum: ["WEB", "MOBILE"], default: "WEB" }
   },
   {
      timestamps: true
   }
)

sessionSchema.statics = {
   async createSession(sessionData) {
      try {
         let session = new this(sessionData)
         const entity = sessionData.entity
         session.firstName = entity.firstName
         session.lastName = entity.lastName
         session.role = entity.role
         session.token = uuidv1()
         let val = new moment().add(config.mobileUserTimeInMins || 43200, 'minutes')
         session.logoutTime = val

         loginSession = await session.save()
         return { token: loginSession }
      } catch (error) {
         throw error
      }
   },
}

module.exports = mongoose.model("LoginSession", sessionSchema)