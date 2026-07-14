using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecureAuthAPI.Migrations
{
    /// <inheritdoc />
    public partial class AddDateTimeExpiration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "DateTimeExpiryTime",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DateTimeExpiryTime",
                table: "AspNetUsers");
        }
    }
}
