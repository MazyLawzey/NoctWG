/* SPDX-License-Identifier: GPL-3.0
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package protocol

// GetRPFTHandler returns the RPFT handler for external access
func (d *Device) GetRPFTHandler() *RPFTHandler {
	return d.rpftHandler
}
