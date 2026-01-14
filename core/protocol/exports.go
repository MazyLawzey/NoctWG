/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package protocol

// GetRPFTHandler returns the RPFT handler for external access
func (d *Device) GetRPFTHandler() *RPFTHandler {
	return d.rpftHandler
}
